use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pnet_relay::RelayServer;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use crate::peer::{ConnectionState, PeerManager};

fn peer(node_id: &str, virtual_ip: &str) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

fn peer_manager() -> Arc<PeerManager> {
    Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ))
}

#[test]
fn relay_pong_updates_runtime_health() {
    let mut diagnostics = RelaySelectionDiagnostics::default();

    record_relay_pong(&mut diagnostics, 900, 1_000);
    assert_eq!(diagnostics.selected_last_pong_at_unix_ms, Some(1_000));
    assert_eq!(diagnostics.selected_last_pong_age_ms, Some(0));
    assert_eq!(diagnostics.selected_last_pong_rtt_ms, Some(100));
    assert_eq!(diagnostics.selected_rtt_ewma_ms, Some(100));
    assert_eq!(diagnostics.selected_jitter_ms, Some(0));
    assert_eq!(diagnostics.selected_pong_count, 1);

    record_relay_pong(&mut diagnostics, 1_000, 1_120);
    assert_eq!(diagnostics.selected_last_pong_rtt_ms, Some(120));
    assert_eq!(diagnostics.selected_rtt_ewma_ms, Some(103));
    assert_eq!(diagnostics.selected_jitter_ms, Some(5));
    assert_eq!(diagnostics.selected_pong_count, 2);

    diagnostics.refresh_runtime_ages();
    assert!(diagnostics.selected_last_pong_age_ms.unwrap() > 0);
}

#[test]
fn relay_runtime_error_helpers_extract_peer_context() {
    assert_eq!(relay_error_code_name(404), "peer_not_found");
    assert_eq!(relay_error_code_name(4999), "error_4999");
    assert_eq!(
        relay_error_peer_id("peer not found: node-b"),
        Some("node-b")
    );
    assert_eq!(
        relay_error_peer_id("peer disconnected: node-b "),
        Some("node-b")
    );
    assert_eq!(
        relay_error_peer_id("peer backpressure: node-b"),
        Some("node-b")
    );
    assert_eq!(relay_error_peer_id("target peer not connected"), None);
}

#[tokio::test]
async fn relay_transport_sends_encrypted_datagrams() {
    let server = RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();

    let peers_a = peer_manager();
    let peers_b = peer_manager();
    peers_a.add_peer(&peer("node-b", "10.20.0.2")).await;
    peers_b.add_peer(&peer("node-a", "10.20.0.1")).await;

    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers_a.clone())
        .await
        .unwrap();
    let (relay_b, rx_b) = RelayTransport::connect(&relay_endpoint, "node-b", peers_b.clone())
        .await
        .unwrap();

    let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
    let inbound_worker = tokio::spawn(relay_b.run_inbound(rx_b, inbound_tx, None));

    let payload = vec![4, 1, 2, 3, 4, 5];
    relay_a
        .send_packet(&EncryptedPeerPacket {
            peer_id: "node-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: payload.clone(),
            is_business: false,
        })
        .await
        .unwrap();

    let received = timeout(Duration::from_secs(2), inbound_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.source, None);
    assert_eq!(
        received.relay_endpoint.as_deref(),
        Some(relay_endpoint.as_str())
    );
    assert_eq!(received.relay_peer_id.as_deref(), Some("node-a"));
    assert_eq!(received.wire_bytes, payload);

    let conn_a = peers_a.get_connection("node-b").await.unwrap();
    assert_eq!(conn_a.state, ConnectionState::Idle);
    assert_eq!(conn_a.relay_server, Some(relay_endpoint.clone()));
    assert_eq!(conn_a.bytes_sent, 0);

    let conn_b = peers_b.get_connection("node-a").await.unwrap();
    assert_eq!(conn_b.state, ConnectionState::Idle);
    assert_eq!(conn_b.relay_server, None);

    inbound_worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn relay_peer_not_found_is_attributed_to_destination() {
    let server = RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();
    let peers = peer_manager();
    peers.add_peer(&peer("node-b", "10.20.0.2")).await;

    let (relay, relay_rx) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (inbound_tx, _inbound_rx) = mpsc::channel(1);
    let inbound_worker = tokio::spawn(relay.clone().run_inbound(relay_rx, inbound_tx, None));

    relay
        .send_packet(&EncryptedPeerPacket {
            peer_id: "node-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: vec![4, 1, 2, 3],
            is_business: false,
        })
        .await
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("node-b").await.unwrap();
            if conn.relay_health.last_error_code.as_deref() == Some("peer_not_found") {
                assert_eq!(
                    conn.relay_health.last_error.as_deref(),
                    Some("peer not found: node-b")
                );
                assert_eq!(conn.state, ConnectionState::Idle);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("relay 404 was not attributed to node-b");

    let diagnostics = peers
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, None);

    inbound_worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn repeated_transient_peer_not_found_is_deduplicated_in_relay_diagnostics() {
    let peers = peer_manager();
    peers.add_peer(&peer("node-b", "10.20.0.2")).await;
    let relay = RelayTransport::connect_for_test("default", "tcp://relay.test:18081", peers);
    let diagnostics = Arc::new(tokio::sync::RwLock::new(
        RelaySelectionDiagnostics::default(),
    ));
    let (relay_tx, relay_rx) = mpsc::channel(4);
    let (inbound_tx, _inbound_rx) = mpsc::channel(1);

    for _ in 0..3 {
        relay_tx
            .send(RelayMessage::Error {
                code: 404,
                message: "peer not found: node-b".to_string(),
            })
            .await
            .unwrap();
    }
    drop(relay_tx);
    relay
        .run_inbound(relay_rx, inbound_tx, Some(diagnostics.clone()))
        .await
        .unwrap();

    let diagnostics = diagnostics.read().await;
    assert_eq!(
        diagnostics.selected_error_count, 1,
        "one transient 404 window must not inflate selected relay errors"
    );
    // A per-peer 404 is deduplicated in its own slot and never overwrites
    // the connection-level health label.
    assert_eq!(
        diagnostics.last_error_code.as_deref(),
        None,
        "a per-peer peer_not_found must not set the connection-level last_error_code"
    );
    assert_eq!(
        diagnostics.last_peer_not_found.as_deref(),
        Some("peer not found: node-b"),
        "the per-peer 404 is recorded in its own dedup slot"
    );
}

#[test]
fn relay_candidate_parses_region_and_legacy_endpoint() {
    let preferred = vec!["cn-east".to_string()];
    let regional = parse_candidate(
        0,
        &RelayCandidateConfig::legacy("cn-east@127.0.0.1:8080"),
        &preferred,
    )
    .unwrap();
    assert_eq!(regional.region, "cn-east");
    assert_eq!(regional.endpoint, "127.0.0.1:8080");
    assert_eq!(regional.audience, None);
    assert_eq!(regional.preference_rank, 0);

    let legacy = parse_candidate(
        1,
        &RelayCandidateConfig::legacy("127.0.0.1:8081"),
        &preferred,
    )
    .unwrap();
    assert_eq!(legacy.region, "default");
    assert_eq!(legacy.endpoint, "127.0.0.1:8081");
    assert_eq!(legacy.preference_rank, 1);
}

#[test]
fn relay_candidate_preserves_catalog_audience() {
    let candidate = parse_candidate(
        0,
        &RelayCandidateConfig::catalog("sg", "relay-sg-1", "tls://relay.example.com:18081"),
        &["sg".to_string()],
    )
    .unwrap();

    assert_eq!(candidate.region, "sg");
    assert_eq!(candidate.audience.as_deref(), Some("relay-sg-1"));
    assert_eq!(candidate.endpoint, "tls://relay.example.com:18081");
    assert_eq!(candidate.preference_rank, 0);
}

#[test]
fn relay_ticket_lookup_uses_catalog_audience_for_tcp_too() {
    let candidate = parse_candidate(
        0,
        &RelayCandidateConfig::catalog("dev", "relay-dev-1", "tcp://127.0.0.1:18081"),
        &[],
    )
    .unwrap();

    assert_eq!(
        relay_ticket_lookup_key(&candidate),
        Some(("relay-dev-1", "dev"))
    );
}

#[tokio::test]
async fn relay_selector_prefers_configured_region() {
    let east = RelayServer::start_random().await.unwrap();
    let west = RelayServer::start_random().await.unwrap();
    let specs = vec![
        RelayCandidateConfig::legacy(format!("east@{}", east.addr)),
        RelayCandidateConfig::legacy(format!("west@{}", west.addr)),
    ];

    let outcome = select_relay(
        &specs,
        &["west".to_string()],
        Duration::from_secs(1),
        "node-a",
        peer_manager(),
        None,
        None,
        true,
        None,
    )
    .await;

    let transport = outcome.transport.as_ref().unwrap();
    assert_eq!(transport.region(), "west");
    assert_eq!(transport.endpoint(), west.addr.to_string());
    assert_eq!(outcome.diagnostics.selected_region.as_deref(), Some("west"));
    assert_eq!(outcome.diagnostics.candidates.len(), 2);
    for candidate in &outcome.diagnostics.candidates {
        match candidate.outcome.as_deref() {
            Some("success") => assert!(candidate.error.is_none()),
            Some("cancelled") => assert_eq!(candidate.error_code.as_deref(), Some("cancelled")),
            other => panic!(
                "healthy local candidate had unexpected outcome {other:?}: {:?}",
                candidate.error
            ),
        }
    }

    drop(outcome);
    east.shutdown().await;
    west.shutdown().await;
}

#[tokio::test]
async fn relay_selector_uses_catalog_order_for_equal_region() {
    // Both peers receive the same catalog.  Equal region preference must
    // have a deterministic catalog-index tie-break; otherwise each peer
    // can choose a different healthy relay purely from connection timing
    // and both sides then see peer_not_found on their isolated relays.
    let primary = RelayServer::start_random().await.unwrap();
    let standby = RelayServer::start_random().await.unwrap();
    let specs = vec![
        RelayCandidateConfig::catalog("local", "relay-primary", primary.addr.to_string()),
        RelayCandidateConfig::catalog("local", "relay-standby", standby.addr.to_string()),
    ];

    let outcome = select_relay(
        &specs,
        &["local".to_string()],
        Duration::from_secs(1),
        "node-a",
        peer_manager(),
        None,
        None,
        true,
        None,
    )
    .await;

    let transport = outcome.transport.as_ref().unwrap();
    assert_eq!(transport.endpoint(), primary.addr.to_string());
    assert_eq!(
        outcome.diagnostics.selected_endpoint.as_deref(),
        Some(primary.addr.to_string().as_str())
    );

    drop(outcome);
    primary.shutdown().await;
    standby.shutdown().await;
}

#[tokio::test]
async fn relay_selector_skips_cooled_down_candidate() {
    let primary = RelayServer::start_random().await.unwrap();
    let standby = RelayServer::start_random().await.unwrap();
    let specs = vec![
        RelayCandidateConfig::legacy(format!("primary@{}", primary.addr)),
        RelayCandidateConfig::legacy(format!("standby@{}", standby.addr)),
    ];
    let mut cooldowns = HashMap::new();
    cooldowns.insert(
        primary.addr.to_string(),
        Instant::now() + Duration::from_secs(30),
    );

    let outcome = select_relay_with_cooldowns(
        &specs,
        &["primary".to_string()],
        Duration::from_secs(1),
        "node-a",
        peer_manager(),
        None,
        None,
        true,
        None,
        &cooldowns,
    )
    .await;

    let transport = outcome.transport.as_ref().unwrap();
    assert_eq!(transport.region(), "standby");
    assert_eq!(transport.endpoint(), standby.addr.to_string());
    assert_eq!(
        outcome.diagnostics.candidates[0].error_code.as_deref(),
        Some("cooling_down")
    );
    assert!(outcome.diagnostics.candidates[0]
        .cooldown_remaining_ms
        .is_some());
    assert!(outcome.diagnostics.candidates[1].error.is_none());

    drop(outcome);
    primary.shutdown().await;
    standby.shutdown().await;
}

#[tokio::test]
async fn relay_selector_falls_back_when_preferred_region_is_unreachable() {
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);
    let fallback = RelayServer::start_random().await.unwrap();
    let specs = vec![
        RelayCandidateConfig::legacy(format!("preferred@{dead_addr}")),
        RelayCandidateConfig::legacy(format!("fallback@{}", fallback.addr)),
    ];

    let outcome = select_relay(
        &specs,
        &["preferred".to_string()],
        Duration::from_secs(1),
        "node-a",
        peer_manager(),
        None,
        None,
        true,
        None,
    )
    .await;

    let transport = outcome.transport.as_ref().unwrap();
    assert_eq!(transport.region(), "fallback");
    assert_eq!(transport.endpoint(), fallback.addr.to_string());
    assert!(outcome.diagnostics.candidates[0].error.is_some());
    assert!(outcome.diagnostics.candidates[1].error.is_none());
    assert_eq!(outcome.diagnostics.last_error, None);

    drop(outcome);
    fallback.shutdown().await;
}

#[tokio::test]
async fn relay_selector_publishes_first_success_without_waiting_for_black_hole_candidate() {
    // One healthy relay plus one "TCP connects but registration never
    // completes" black hole.  First-success must publish the healthy one in
    // about the bounded preference window, NOT wait for the black hole's
    // connect/register timeout.  The still-running black-hole task is
    // cancelled and recorded distinctly from failed/timeout.
    let healthy = RelayServer::start_random().await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blackhole_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Accept and hold the socket open, never sending a
                // Registered frame: the DERP registration never completes.
                let _ = tokio::io::copy(&mut sock, &mut tokio::io::sink()).await;
            });
        }
    });

    let specs = vec![
        RelayCandidateConfig::legacy(format!("healthy@{}", healthy.addr)),
        RelayCandidateConfig::legacy(format!("blackhole@{blackhole_addr}")),
    ];
    let started = Instant::now();
    let outcome = select_relay(
        &specs,
        &[],
        Duration::from_secs(10),
        "node-a",
        peer_manager(),
        None,
        None,
        true,
        None,
    )
    .await;
    let elapsed = started.elapsed();
    let transport = outcome.transport.as_ref().unwrap();
    assert_eq!(transport.endpoint(), healthy.addr.to_string());
    assert!(
        elapsed < Duration::from_secs(3),
        "first-success must NOT wait the black hole's 10s timeout; took {elapsed:?}"
    );
    // The healthy candidate is a success; the black hole is CANCELLED (not
    // failed/timeout) because it was still in flight when the selection
    // published and aborted it.
    let healthy_diag = outcome
        .diagnostics
        .candidates
        .iter()
        .find(|c| c.endpoint == healthy.addr.to_string())
        .unwrap();
    assert_eq!(healthy_diag.outcome.as_deref(), Some("success"));
    let bh_diag = outcome
        .diagnostics
        .candidates
        .iter()
        .find(|c| c.endpoint == blackhole_addr.to_string())
        .unwrap();
    assert_eq!(
        bh_diag.outcome.as_deref(),
        Some("cancelled"),
        "the in-flight black-hole candidate must be recorded as cancelled, got {:?}",
        bh_diag.outcome
    );

    drop(outcome);
    server.abort();
    healthy.shutdown().await;
}
