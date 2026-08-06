use std::net::Ipv4Addr;
use std::time::Duration;

use p2pnet_crypto::NodeIdentity;
use p2pnet_nat::build_authenticated_punch_ack;
use p2pnet_nat::build_authenticated_punch_packet;
use p2pnet_tun::{Ipv4Packet, MockTunDevice};
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use crate::dataplane::DataPlane;
use crate::peer::{ConnectionState, ProbeBindingStage, ProbeKeyRole};
use crate::transport::WireGuardTransport;

fn peer(node_id: &str, virtual_ip: &str, endpoint: Option<SocketAddr>) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: endpoint.map(|addr| addr.to_string()).unwrap_or_default(),
        nat_type: "FullCone".to_string(),
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

fn peer_with_public_key(
    node_id: &str,
    virtual_ip: &str,
    public_key: String,
    endpoint: Option<SocketAddr>,
) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key,
        endpoint: endpoint.map(|addr| addr.to_string()).unwrap_or_default(),
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

fn config_for_identity(identity: &NodeIdentity, node_id: &str) -> Config {
    let mut config = Config::generate_default("http://ctrl.test", "default").unwrap();
    config.node.node_id = node_id.to_string();
    config.node.public_key = hex::encode(identity.public_key());
    config.node.private_key = hex::encode(identity.private_key());
    config
}

async fn drain_udp_quiet(socket: &UdpSocket, quiet: Duration) {
    let mut buf = [0u8; 512];
    while timeout(quiet, socket.recv_from(&mut buf)).await.is_ok() {}
}

#[test]
fn legacy_ack_matching_accepts_port_drift_but_rejects_ip_drift() {
    let pending = PendingProbe {
        sent_at: Instant::now(),
        endpoint: "203.0.113.10:40000".parse().unwrap(),
        local_endpoint: None,
        socket_index: 2,
        generation: 7,
        peer_id: Some("peer-b".to_string()),
        purpose: PendingProbePurpose::ConnectivityCheck,
        accepts_authenticated_ack: true,
        accepts_legacy_ack: true,
        socket_epoch: 0,
        cleanup_epoch: 0,
    };

    assert!(legacy_ack_matches_pending(
        &pending,
        "203.0.113.10:40123".parse().unwrap(),
        7,
        2,
    ));
    assert!(!legacy_ack_matches_pending(
        &pending,
        "203.0.113.11:40123".parse().unwrap(),
        7,
        2,
    ));
    assert!(!legacy_ack_matches_pending(
        &pending,
        "203.0.113.10:40123".parse().unwrap(),
        8,
        2,
    ));
}

#[test]
fn probe_rx_snapshot_delta_is_saturating() {
    let newer = UdpProbeRxSnapshot {
        known_peer_ip_datagrams_received: 12,
        authenticated_probe_packets_received: 10,
        authenticated_probe_acks_observed: 5,
        authenticated_probe_acks_unmatched: 2,
        legacy_probe_acks_observed: 4,
        legacy_probe_acks_unmatched: 1,
        probe_acks_received: 3,
    };
    let older = UdpProbeRxSnapshot {
        known_peer_ip_datagrams_received: 9,
        authenticated_probe_packets_received: 7,
        authenticated_probe_acks_observed: 9,
        authenticated_probe_acks_unmatched: 1,
        legacy_probe_acks_observed: 2,
        legacy_probe_acks_unmatched: 5,
        probe_acks_received: 9,
    };

    assert_eq!(
        newer.delta_since(older),
        UdpProbeRxSnapshot {
            known_peer_ip_datagrams_received: 3,
            authenticated_probe_packets_received: 3,
            authenticated_probe_acks_observed: 0,
            authenticated_probe_acks_unmatched: 1,
            legacy_probe_acks_observed: 2,
            legacy_probe_acks_unmatched: 0,
            probe_acks_received: 0,
        }
    );
}

#[test]
fn remote_scatter_punch_deadline_keeps_wide_sweep_alive() {
    let candidates: Vec<SocketAddr> = (0..831)
        .map(|i| {
            format!("203.0.113.10:{}", 40_000 + (i % 1000) as u16)
                .parse()
                .unwrap()
        })
        .collect();
    let deadline = estimate_remote_scatter_punch_deadline(
        &candidates,
        Duration::from_millis(200),
        6,
        3,
        Duration::from_secs(2),
    );
    assert!(
        deadline >= Duration::from_secs(45),
        "an 831-candidate remote scatter sweep must keep at least the 45s floor, got {deadline:?}"
    );
    assert!(
        deadline > Duration::from_secs(24),
        "remote scatter deadline must exceed the fixed 24s bound, got {deadline:?}"
    );
}

#[tokio::test]
async fn authenticated_punch_admission_detects_replay_and_rate_limits() {
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
        .await
        .unwrap();
    let source: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let nonce = [7u8; 8];

    assert_eq!(
        transport
            .admit_authenticated_punch("peer-b", 1, PunchPacketKind::Punch, nonce, source)
            .await,
        AuthenticatedPunchAdmission::Accepted
    );
    assert_eq!(
        transport
            .admit_authenticated_punch("peer-b", 1, PunchPacketKind::Punch, nonce, source)
            .await,
        AuthenticatedPunchAdmission::Replay
    );

    let rate_source: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    for index in 0..AUTH_PUNCH_RATE_LIMIT_PER_SOURCE {
        let mut nonce = [0u8; 8];
        nonce[0] = index as u8;
        assert_eq!(
            transport
                .admit_authenticated_punch("peer-b", 2, PunchPacketKind::Punch, nonce, rate_source)
                .await,
            AuthenticatedPunchAdmission::Accepted
        );
    }
    assert_eq!(
        transport
            .admit_authenticated_punch("peer-b", 2, PunchPacketKind::Punch, [99u8; 8], rate_source)
            .await,
        AuthenticatedPunchAdmission::RateLimited
    );
}

#[tokio::test]
async fn inbound_counts_known_peer_ip_and_unmatched_authenticated_ack() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let known_candidate: SocketAddr = "127.0.0.1:50999".parse().unwrap();

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(known_candidate),
        ))
        .await;
    assert!(
        peers
            .has_known_public_candidate_ip("127.0.0.1".parse().unwrap())
            .await
    );
    assert!(
        !peers
            .has_known_public_candidate_ip("198.51.100.9".parse().unwrap())
            .await
    );

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let generation = peers.current_network_generation().await;

    let ack = build_authenticated_punch_ack([42u8; 8], "peer-b", "peer-a", generation, &key);
    sender.send_to(&ack, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if transport.socket_pool_diagnostics().await[0]
                .authenticated_probe_acks_unmatched
                >= 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].known_peer_ip_datagrams_received, 1);
    assert_eq!(diagnostics[0].authenticated_probe_packets_received, 1);
    assert_eq!(diagnostics[0].authenticated_probe_acks_observed, 1);
    assert_eq!(diagnostics[0].authenticated_probe_acks_unmatched, 1);
    assert_eq!(diagnostics[0].probe_acks_received, 0);

    // An invalid-MAC authenticated probe from the same known peer IP is counted
    // at the raw-IP and Probe v2 framing layers, then fails MAC validation.
    let (mut bad_probe, _nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &key);
    *bad_probe.last_mut().unwrap() ^= 0x01;
    sender.send_to(&bad_probe, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if transport.socket_pool_diagnostics().await[0].authenticated_probe_invalid_mac >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].known_peer_ip_datagrams_received, 2);
    assert_eq!(diagnostics[0].authenticated_probe_packets_received, 2);
    assert_eq!(diagnostics[0].authenticated_probe_invalid_mac, 1);
    assert_eq!(diagnostics[0].authenticated_probe_acks_observed, 1);
    assert_eq!(diagnostics[0].authenticated_probe_acks_unmatched, 1);
    assert_eq!(diagnostics[0].probe_acks_received, 0);

    worker.abort();
}

fn hard_nat_candidate_report(
    filtering_behavior: p2pnet_nat::FilteringBehavior,
) -> CandidateGatherReport {
    CandidateGatherReport {
        candidates: Vec::new(),
        nat_profile: p2pnet_nat::NatProfile {
            local_addr: "0.0.0.0:0".to_string(),
            observations: Vec::new(),
            udp_blocked: false,
            public_endpoint: Some("203.0.113.10:40000".to_string()),
            public_ip_stable: Some(true),
            public_port_stable: Some(false),
            port_preserved: Some(false),
            port_delta: Some(1),
            likely_symmetric: Some(true),
            mapping_behavior: MappingBehavior::AddressOrPortDependent,
            filtering_behavior,
            hairpin_behavior: p2pnet_nat::HairpinBehavior::Unknown,
            mapping_lifetime: p2pnet_nat::MappingLifetime::Unknown,
            prediction_candidate: true,
            predicted_endpoints: vec!["203.0.113.10:40001".to_string()],
            birthday_candidate: true,
            confidence: 90,
        },
    }
}

#[test]
fn socket_pool_activates_for_mapping_dependent_nat_with_unknown_filtering() {
    let report = hard_nat_candidate_report(p2pnet_nat::FilteringBehavior::Unknown);

    assert!(socket_pool_is_eligible(&report));
}

#[test]
fn socket_pool_rejects_udp_blocked_nat_profile() {
    let mut report = hard_nat_candidate_report(p2pnet_nat::FilteringBehavior::UdpBlocked);
    report.nat_profile.udp_blocked = true;

    assert!(!socket_pool_is_eligible(&report));
}

#[tokio::test]
async fn global_outbound_probe_budget_limits_across_transports() {
    let global_budget = Arc::new(GlobalOutboundProbeBudget::new());
    let transport_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
        .await
        .unwrap()
        .with_global_probe_budget(global_budget.clone());
    let peer_id = "peer-global";
    let endpoint: SocketAddr = "203.0.113.1:49999".parse().unwrap();

    for _ in 0..OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP {
        assert_eq!(
            global_budget.admit(peer_id, endpoint).await,
            OutboundProbeAdmission::Accepted
        );
    }

    assert_eq!(
        transport_b
            .admit_outbound_connectivity_probe(peer_id, endpoint)
            .await,
        OutboundProbeAdmission::GlobalRemoteIpRateLimited
    );
}

#[tokio::test]
async fn outbound_probe_budget_limits_across_peers_on_same_network() {
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
        .await
        .unwrap();

    {
        let now = Instant::now();
        let mut budget = transport.outbound_probe_budget.lock().await;
        budget.insert(
            OutboundProbeBudgetKey::Network,
            std::iter::repeat_n(now, OUTBOUND_PROBE_BUDGET_PER_NETWORK).collect(),
        );
    }

    assert_eq!(
        transport
            .admit_outbound_connectivity_probe("peer-extra", "127.9.9.9:49999".parse().unwrap(),)
            .await,
        OutboundProbeAdmission::NetworkRateLimited
    );
}

#[test]
fn adaptive_probe_schedule_covers_all_candidates_on_final_round() {
    let candidates = vec![
        "127.0.0.1:10001".parse().unwrap(),
        "127.0.0.1:10002".parse().unwrap(),
        "127.0.0.1:10003".parse().unwrap(),
        "127.0.0.1:10004".parse().unwrap(),
        "127.0.0.1:10005".parse().unwrap(),
    ];

    let schedule = build_probe_schedule(&candidates, Duration::from_millis(200), 3);

    assert_eq!(schedule.len(), 3);
    assert_eq!(schedule[0].delay_before, Duration::ZERO);
    assert_eq!(schedule[0].endpoints, candidates);
    assert_eq!(schedule[1].delay_before, Duration::from_millis(60));
    assert_eq!(schedule[1].endpoints, candidates);
    assert_eq!(schedule[2].delay_before, Duration::from_millis(140));
    assert_eq!(schedule[2].endpoints, candidates);
}

#[test]
fn adaptive_probe_schedule_expands_large_candidate_sets_quickly() {
    let candidates = (0..48)
        .map(|i| format!("127.0.0.1:{}", 12_000 + i).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let schedule = build_probe_schedule(&candidates, Duration::from_millis(200), 4);

    assert_eq!(schedule.len(), 4);
    assert_eq!(schedule[0].endpoints.len(), 48);
    assert_eq!(schedule[1].endpoints.len(), 24);
    assert_eq!(schedule[2].endpoints.len(), 48);
    assert_eq!(schedule[3].endpoints.len(), 48);
}

#[test]
fn adaptive_probe_schedule_covers_large_candidate_tail_before_retries() {
    let candidates = (0..384)
        .map(|i| format!("127.0.0.1:{}", 20_000 + i).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let schedule = build_probe_schedule(&candidates, Duration::from_millis(200), 10);

    assert_eq!(schedule[0].endpoints, candidates);
    assert_eq!(schedule[1].endpoints, candidates[..24]);
}

#[test]
fn adaptive_probe_schedule_preserves_single_attempt_full_coverage() {
    let candidates = vec![
        "127.0.0.1:11001".parse().unwrap(),
        "127.0.0.1:11002".parse().unwrap(),
        "127.0.0.1:11001".parse().unwrap(),
    ];

    let schedule = build_probe_schedule(&candidates, Duration::from_millis(200), 1);

    assert_eq!(schedule.len(), 1);
    assert_eq!(schedule[0].delay_before, Duration::ZERO);
    assert_eq!(
        schedule[0].endpoints,
        vec![
            "127.0.0.1:11001".parse().unwrap(),
            "127.0.0.1:11002".parse().unwrap(),
        ]
    );
}

fn establish_sessions() -> (TransportSession, TransportSession) {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();

    let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut responder = HandshakeResponder::new(node_b, None);

    let init = initiator.create_initiation().unwrap();
    let (response, node_b_keys) = responder.consume_initiation_and_respond(&init).unwrap();
    let node_a_keys = initiator.consume_response(&response).unwrap();

    (
        TransportSession::new(node_a_keys),
        TransportSession::new(node_b_keys),
    )
}
