use std::net::Ipv4Addr;
use std::time::Duration;

use p2pnet_crypto::NodeIdentity;
use p2pnet_nat::build_authenticated_punch_packet;
use p2pnet_tun::{Ipv4Packet, MockTunDevice};
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use crate::dataplane::DataPlane;
use crate::peer::ConnectionState;
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
            std::iter::repeat(now)
                .take(OUTBOUND_PROBE_BUDGET_PER_NETWORK)
                .collect(),
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
    assert_eq!(schedule[0].endpoints.len(), 24);
    assert_eq!(schedule[1].endpoints.len(), 24);
    assert_eq!(schedule[2].endpoints.len(), 48);
    assert_eq!(schedule[3].endpoints.len(), 48);
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
