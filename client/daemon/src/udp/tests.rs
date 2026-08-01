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

fn unique_global_probe_budget_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "p2wlan-{name}-{}-{}.tsv",
        std::process::id(),
        unix_time_millis()
    ))
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
    let path = unique_global_probe_budget_path("global-probe-budget");
    let transport_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
        .await
        .unwrap()
        .with_global_probe_budget_path(path.clone());
    let peer_id = "peer-global";
    let endpoint: SocketAddr = "203.0.113.1:49999".parse().unwrap();
    let remote_ip_key = global_probe_remote_ip_key(peer_id, endpoint.ip());
    let now_ms = unix_time_millis().saturating_add(OUTBOUND_PROBE_BUDGET_WINDOW.as_millis() as u64);
    let mut entries = Vec::new();

    for _ in 0..OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP {
        entries.push((now_ms, remote_ip_key.clone()));
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    write_global_probe_budget_entries(&mut file, &entries).unwrap();

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

#[tokio::test]
async fn gathers_host_candidates_for_bound_udp_port() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let local_port = transport.local_addr().unwrap().port();

    let candidates = transport
        .gather_candidates(Vec::new(), Duration::from_millis(100))
        .await
        .unwrap();

    assert!(!candidates.is_empty());
    assert!(candidates
        .iter()
        .any(|candidate| candidate.ends_with(&format!(":{local_port}"))));
}

#[tokio::test]
async fn punch_candidates_sends_probe_datagrams() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();

    let sent = transport
        .punch_candidates("peer-b", vec![receiver_addr], Duration::from_millis(10), 2)
        .await
        .unwrap();

    assert_eq!(sent, 2);

    let mut buf = [0u8; 64];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = decode_punch_packet(&buf[..n]).unwrap();
    assert_eq!(packet.kind, PunchPacketKind::Punch);
}

#[tokio::test]
async fn punch_candidates_respects_outbound_probe_budget_per_remote_ip() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    {
        let now = Instant::now();
        let mut budget = transport.outbound_probe_budget.lock().await;
        budget.insert(
            OutboundProbeBudgetKey::PeerRemoteIp(
                "peer-b".to_string(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ),
            std::iter::repeat(now)
                .take(OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP - 8)
                .collect(),
        );
    }

    let candidates = (0..16)
        .map(|offset| format!("127.0.0.1:{}", 30_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let sent = transport
        .punch_candidates("peer-b", candidates, Duration::ZERO, 1)
        .await
        .unwrap();

    assert_eq!(sent as usize, 8);
    let diagnostics = peers.diagnostics().await;
    let event = diagnostics[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "probe_budget_limited")
        .expect("budget-limited probe pass should be recorded");
    assert_eq!(event.sent_probes, Some(sent));
    assert!(event.detail.contains("remote_ip_rate_limited"));
}

#[tokio::test]
async fn qualified_socket_pool_probes_from_each_bound_socket() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();

    assert_eq!(transport.socket_count(), 3);
    assert!(!transport.socket_pool_active());
    transport.set_socket_pool_active(true);
    assert!(transport.socket_pool_active());

    let sent = transport
        .punch_candidates("peer-b", vec![receiver_addr], Duration::ZERO, 1)
        .await
        .unwrap();
    assert_eq!(sent, 3);

    let mut sources = std::collections::HashSet::new();
    let mut buf = [0u8; 64];
    for _ in 0..3 {
        let (n, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_punch_packet(&buf[..n]).unwrap().kind,
            PunchPacketKind::Punch
        );
        sources.insert(source);
    }
    assert_eq!(sources.len(), 3);
    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(
        diagnostics
            .iter()
            .map(|member| member.probes_sent)
            .collect::<Vec<_>>(),
        vec![1, 1, 1]
    );
}

#[tokio::test]
async fn live_candidate_refresh_advertises_each_qualified_pool_mapping() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let inbound_worker = tokio::spawn(transport.clone().run_inbound(inbound_tx));

    let first_stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_stun_addr = first_stun.local_addr().unwrap();
    let first_worker = tokio::spawn(async move {
        for _ in 0..3 {
            let mut buf = [0u8; 2048];
            let (n, client_addr) = first_stun.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::decode(&buf[..n]).unwrap();
            let mapped = SocketAddr::new("203.0.113.7".parse().unwrap(), client_addr.port());
            let mut response =
                StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
            response.add_attribute(StunAttribute::XorMappedAddress(mapped));
            first_stun
                .send_to(&response.encode(), client_addr)
                .await
                .unwrap();
        }
    });

    let second_stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_stun_addr = second_stun.local_addr().unwrap();
    let second_worker = tokio::spawn(async move {
        for _ in 0..3 {
            let mut buf = [0u8; 2048];
            let (n, client_addr) = second_stun.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::decode(&buf[..n]).unwrap();
            let mapped = SocketAddr::new(
                "203.0.113.7".parse().unwrap(),
                client_addr.port().saturating_add(1),
            );
            let mut response =
                StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
            response.add_attribute(StunAttribute::XorMappedAddress(mapped));
            second_stun
                .send_to(&response.encode(), client_addr)
                .await
                .unwrap();
        }
    });

    let report = transport
        .gather_candidate_report_live(
            vec![first_stun_addr, second_stun_addr],
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert!(transport.socket_pool_active());
    let public_candidates = report
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.endpoint.ip == "203.0.113.7"
                && candidate.source == p2pnet_nat::CandidateSource::StunObserved
        })
        .count();
    assert_eq!(public_candidates, 6);
    let predicted_candidates = report
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.endpoint.ip == "203.0.113.7"
                && candidate.source == p2pnet_nat::CandidateSource::Predicted
        })
        .count();
    assert!(
        predicted_candidates >= 8,
        "each qualified pool socket should contribute predicted ports; got {predicted_candidates}"
    );
    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].stun_mappings_discovered, 0);
    assert_eq!(diagnostics[1].stun_mappings_discovered, 2);
    assert_eq!(diagnostics[2].stun_mappings_discovered, 2);

    first_worker.await.unwrap();
    second_worker.await.unwrap();
    inbound_worker.abort();
}

#[tokio::test]
async fn probe_ack_pins_peer_to_the_socket_that_received_it() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers
        .add_peer(&peer("peer-b", "10.20.0.9", Some(receiver_addr)))
        .await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(2)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);
    let primary_addr = transport.local_addr().unwrap();
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(inbound_tx));

    assert_eq!(
        transport
            .punch_candidates("peer-b", vec![receiver_addr], Duration::ZERO, 1)
            .await
            .unwrap(),
        2
    );

    let mut buf = [0u8; 64];
    let mut secondary_probe = None;
    for _ in 0..2 {
        let (n, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = decode_punch_packet(&buf[..n]).unwrap();
        if source != primary_addr {
            secondary_probe = Some((packet.nonce, source));
        }
    }
    let (nonce, secondary_source) = secondary_probe.expect("expected a pool probe");
    receiver
        .send_to(&build_punch_ack(nonce), secondary_source)
        .await
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if transport
                .peer_socket_affinity
                .lock()
                .await
                .get("peer-b")
                .copied()
                == Some(1)
            {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ACK should pin the peer to the secondary socket");

    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[1].probe_acks_received, 1);

    worker.abort();
}

#[tokio::test]
async fn send_probe_retransmits_punch_burst() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();

    let nonce = transport.send_probe(None, receiver_addr).await.unwrap();

    let mut buf = [0u8; 64];
    for _ in 0..=PUNCH_PROBE_RETRANSMIT_DELAYS_MS.len() {
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = decode_punch_packet(&buf[..n]).unwrap();
        assert_eq!(packet.kind, PunchPacketKind::Punch);
        assert_eq!(packet.nonce, nonce);
    }
}

#[tokio::test]
async fn inbound_punch_sends_ack_burst() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let punch = build_punch_packet();
    let nonce = decode_punch_packet(&punch).unwrap().nonce;
    sender.send_to(&punch, local_addr).await.unwrap();

    let mut buf = [0u8; 64];
    for _ in 0..=PUNCH_ACK_RETRANSMIT_DELAYS_MS.len() {
        let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = decode_punch_packet(&buf[..n]).unwrap();
        assert_eq!(packet.kind, PunchPacketKind::Ack);
        assert_eq!(packet.nonce, nonce);
    }

    worker.abort();
}

#[tokio::test]
async fn send_probe_uses_authenticated_v2_when_key_is_available() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(receiver_addr),
        ))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    transport
        .send_probe(Some("peer-b"), receiver_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert!(decode_punch_packet(&buf[..n]).is_none());
    let identity = peek_authenticated_punch_identity(&buf[..n]).unwrap();
    assert_eq!(identity.kind, PunchPacketKind::Punch);
    assert_eq!(identity.source_node_id, "peer-a");
    assert_eq!(identity.target_node_id, "peer-b");
    assert!(!identity.use_candidate);

    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let packet = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(packet.kind, PunchPacketKind::Punch);
    assert_eq!(packet.source_node_id.as_deref(), Some("peer-a"));
    assert_eq!(packet.target_node_id.as_deref(), Some("peer-b"));
    assert!(!packet.use_candidate);
    assert!(packet.authenticated);

    let mut compat_buf = [0u8; 512];
    let (compat_n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut compat_buf))
        .await
        .unwrap()
        .unwrap();
    let compat_packet = decode_punch_packet(&compat_buf[..compat_n]).unwrap();
    assert_eq!(compat_packet.kind, PunchPacketKind::Punch);
    assert_eq!(compat_packet.nonce, packet.nonce);
}

#[tokio::test]
async fn send_nomination_probe_sets_use_candidate_flag() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(receiver_addr),
        ))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    transport
        .send_nomination_probe("peer-b", receiver_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let packet = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(packet.kind, PunchPacketKind::Punch);
    assert!(packet.use_candidate);
    assert!(packet.authenticated);
}

#[tokio::test]
async fn legacy_probe_ack_confirms_authenticated_probe_for_old_peer() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let remote_candidate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_candidate_addr = remote_candidate.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(remote_candidate_addr),
        ))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    transport
        .send_probe(Some("peer-b"), remote_candidate_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), remote_candidate.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(peek_authenticated_punch_identity(&buf[..n]).is_some());

    let (legacy_n, _from) = timeout(Duration::from_secs(1), remote_candidate.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let legacy_probe = decode_punch_packet(&buf[..legacy_n]).unwrap();
    assert_eq!(legacy_probe.kind, PunchPacketKind::Punch);

    remote_candidate
        .send_to(&build_punch_ack(legacy_probe.nonce), local_addr)
        .await
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("peer-b").await.unwrap();
            if conn.endpoint == Some(remote_candidate_addr)
                && conn.direct_health.consecutive_failures == 0
                && conn.candidate_pairs.iter().any(|pair| {
                    pair.remote_endpoint == remote_candidate_addr && pair.success_count > 0
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].probe_acks_received, 1);
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(
        conn.candidate_sources
            .get(&remote_candidate_addr.to_string()),
        Some(&crate::peer::CandidatePairSource::Learned)
    );

    worker.abort();
}

#[tokio::test]
async fn sends_encrypted_packet_to_peer_endpoint() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = peer_manager();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(receiver_addr)))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let payload = vec![4, 1, 2, 3, 4, 5, 6, 7];

    let sent = transport
        .send_packet(&EncryptedPeerPacket {
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: payload.clone(),
        })
        .await
        .unwrap();
    assert_eq!(sent, Some(payload.len()));

    let mut buf = [0u8; 128];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], payload.as_slice());
    assert_eq!(peers.get_connection("peer-b").await.unwrap().bytes_sent, 0);
}

#[tokio::test]
async fn drops_packet_when_endpoint_is_unknown() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();

    let sent = transport
        .send_packet(&EncryptedPeerPacket {
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: vec![4, 1, 2, 3],
        })
        .await
        .unwrap();

    assert_eq!(sent, None);
}

#[tokio::test]
async fn run_outbound_sends_wireguard_datagram_that_peer_can_decrypt() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = peer_manager();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(receiver_addr)))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_outbound(rx));

    let (mut node_a_session, mut node_b_session) = establish_sessions();
    let ip_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"ping",
    );
    let wire_bytes = node_a_session.encrypt_to_bytes(&ip_packet).unwrap();

    tx.send(EncryptedPeerPacket {
        peer_id: "peer-b".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        wire_bytes,
    })
    .await
    .unwrap();

    let mut buf = [0u8; 2048];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let decrypted = node_b_session.decrypt_from_bytes(&buf[..n]).unwrap();
    assert_eq!(decrypted, ip_packet);

    worker.abort();
}

#[tokio::test]
async fn run_inbound_emits_received_encrypted_datagram() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = vec![4, 9, 8, 7, 6, 5];
    sender.send_to(&payload, local_addr).await.unwrap();

    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.source, Some(sender.local_addr().unwrap()));
    assert_eq!(received.wire_bytes, payload);

    worker.abort();
}

#[tokio::test]
async fn live_stun_refresh_does_not_steal_encrypted_datagrams() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let inbound_worker = tokio::spawn(transport.clone().run_inbound(tx));

    let stun_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_server.local_addr().unwrap();
    let stun_worker = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (n, client_addr) = stun_server.recv_from(&mut buf).await.unwrap();
        let request = StunMessage::decode(&buf[..n]).unwrap();
        let mapped: SocketAddr = "203.0.113.7:45678".parse().unwrap();
        let mut response =
            StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
        response.add_attribute(StunAttribute::XorMappedAddress(mapped));
        stun_server
            .send_to(&response.encode(), client_addr)
            .await
            .unwrap();
    });

    let refresh = {
        let transport = transport.clone();
        tokio::spawn(async move {
            transport
                .gather_candidate_report_live(vec![stun_addr], Duration::from_secs(1))
                .await
        })
    };

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let encrypted = vec![4, 0x91, 0x82, 0x73, 0x64];
    sender.send_to(&encrypted, local_addr).await.unwrap();

    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.wire_bytes, encrypted);
    assert_eq!(received.source, Some(sender.local_addr().unwrap()));

    let report = refresh.await.unwrap().unwrap();
    assert!(report.candidates.iter().any(|candidate| {
        candidate.endpoint.to_string() == "203.0.113.7:45678"
            && candidate.source == p2pnet_nat::CandidateSource::StunObserved
    }));
    assert_eq!(report.nat_profile.observations.len(), 1);
    assert!(report.nat_profile.observations[0].error.is_none());

    stun_worker.await.unwrap();
    inbound_worker.abort();
}

#[tokio::test]
async fn run_inbound_acks_punch_and_does_not_forward_to_wireguard() {
    let peers = peer_manager();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();

    peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;
    peers
        .add_candidates("peer-b", &[sender_addr.to_string()])
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    sender
        .send_to(&p2pnet_nat::build_punch_packet(), local_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let ack = decode_punch_packet(&buf[..n]).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);

    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(sender_addr));
    assert_eq!(conn.state.to_string(), "hole_punching");
    assert!(conn.direct_health.last_success_at.is_some());

    worker.abort();
}

#[tokio::test]
async fn run_inbound_accepts_authenticated_peer_reflexive_probe() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            None,
        ))
        .await;

    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let (observation_tx, mut observation_rx) = mpsc::channel(4);
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a")
        .with_peer_reflexive_observer(observation_tx);
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let (probe, nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
    sender.send_to(&probe, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);
    assert_eq!(ack.nonce, nonce);
    assert_eq!(ack.source_node_id.as_deref(), Some("peer-a"));
    assert_eq!(ack.target_node_id.as_deref(), Some("peer-b"));
    assert!(!ack.use_candidate);

    let mut saw_triggered_check = false;
    for _ in 0..8 {
        let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        if let Some(identity) = peek_authenticated_punch_identity(&buf[..n]) {
            if identity.kind == PunchPacketKind::Punch
                && identity.source_node_id == "peer-a"
                && identity.target_node_id == "peer-b"
            {
                let triggered = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
                assert_eq!(triggered.kind, PunchPacketKind::Punch);
                saw_triggered_check = true;
                break;
            }
        }
    }
    assert!(
        saw_triggered_check,
        "inbound authenticated probe should trigger an immediate reverse check"
    );

    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());

    let observation = timeout(Duration::from_secs(1), observation_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observation.peer_id, "peer-b");
    assert_eq!(observation.observed_endpoint, sender_addr);

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(sender_addr));
    assert!(conn.candidates.contains(&sender_addr.to_string()));
    assert_eq!(conn.state.to_string(), "hole_punching");
    assert!(conn.direct_health.last_success_at.is_some());

    worker.abort();
}

#[tokio::test]
async fn replayed_authenticated_punch_gets_idempotent_ack_without_state_update() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            None,
        ))
        .await;

    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let (probe, nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
    sender.send_to(&probe, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let first_ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(first_ack.kind, PunchPacketKind::Ack);
    assert_eq!(first_ack.nonce, nonce);
    drain_udp_quiet(&sender, Duration::from_millis(150)).await;

    let first_success_count = peers
        .get_connection("peer-b")
        .await
        .unwrap()
        .direct_health
        .success_count;

    sender.send_to(&probe, local_addr).await.unwrap();
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let replay_ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(replay_ack.kind, PunchPacketKind::Ack);
    assert_eq!(replay_ack.nonce, nonce);

    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(sender_addr));
    assert_eq!(conn.direct_health.success_count, first_success_count);

    worker.abort();
}

#[tokio::test]
async fn run_inbound_rejects_authenticated_probe_with_invalid_mac() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            None,
        ))
        .await;

    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut probe, _nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
    let last = probe.last_mut().unwrap();
    *last ^= 0x80;
    sender.send_to(&probe, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    assert!(
        timeout(Duration::from_millis(150), sender.recv_from(&mut buf))
            .await
            .is_err()
    );
    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert!(conn.candidates.is_empty());

    worker.abort();
}

#[tokio::test]
async fn probe_ack_records_peer_round_trip_latency() {
    let peers = peer_manager();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();

    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    transport
        .send_probe(Some("peer-b"), remote_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, _from) = timeout(Duration::from_secs(1), remote.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let probe = decode_punch_packet(&buf[..n]).unwrap();
    remote
        .send_to(&build_punch_ack(probe.nonce), local_addr)
        .await
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let diagnostics = peers.diagnostics().await;
            if diagnostics[0].direct.latency_ms.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let diagnostics = peers.diagnostics().await;
    assert!(diagnostics[0].direct.latency_ms.is_some());
    assert_eq!(diagnostics[0].direct.consecutive_failures, 0);

    worker.abort();
}

#[tokio::test]
async fn keepalive_ack_timeout_degrades_direct_after_three_misses() {
    let peers = peer_manager();
    let silent_remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = silent_remote.local_addr().unwrap();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
        .await;
    peers
        .record_direct_probe_success_with_latency(
            "peer-b",
            remote_addr,
            Some(Duration::from_millis(5)),
        )
        .await;
    peers
        .record_direct_success("peer-b", Some(remote_addr))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();

    transport
        .run_keepalive_round(Duration::from_millis(10))
        .await;
    let after_one = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(after_one.state, ConnectionState::Direct);
    assert_eq!(after_one.direct_health.consecutive_failures, 1);
    assert!(after_one
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_check_sent"));
    assert!(after_one
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_timeout"));

    transport
        .run_keepalive_round(Duration::from_millis(10))
        .await;
    transport
        .run_keepalive_round(Duration::from_millis(10))
        .await;
    let after_three = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(after_three.state, ConnectionState::FallbackToRelay);
    assert_eq!(after_three.direct_health.consecutive_failures, 3);
    assert_eq!(
        after_three.direct_health.last_error_code.as_deref(),
        Some(crate::peer::REASON_DIRECT_KEEPALIVE_TIMEOUT)
    );
}

#[tokio::test]
async fn matching_keepalive_ack_preserves_direct_health() {
    let peers = peer_manager();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
        .await;
    peers
        .record_direct_probe_success_with_latency(
            "peer-b",
            remote_addr,
            Some(Duration::from_millis(5)),
        )
        .await;
    peers
        .record_direct_success("peer-b", Some(remote_addr))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(1);
    let inbound_worker = tokio::spawn(transport.clone().run_inbound(tx));
    let responder = tokio::spawn(async move {
        let mut buf = [0u8; 256];
        let (n, _) = remote.recv_from(&mut buf).await.unwrap();
        let probe = decode_punch_packet(&buf[..n]).unwrap();
        remote
            .send_to(&build_punch_ack(probe.nonce), local_addr)
            .await
            .unwrap();
    });

    transport
        .run_keepalive_round(Duration::from_millis(100))
        .await;
    responder.await.unwrap();

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_health.consecutive_failures, 0);
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_check_sent"));
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_ack_received"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_timeout"));

    inbound_worker.abort();
}

#[tokio::test]
async fn authenticated_probe_ack_learns_peer_reflexive_source_without_confirming_data() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let remote_candidate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_candidate_addr = remote_candidate.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(remote_candidate_addr),
        ))
        .await;
    let key = peers.probe_key_for_peer("peer-b").await.unwrap();

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    transport
        .send_probe(Some("peer-b"), remote_candidate_addr)
        .await
        .unwrap();
    let mut probe_buf = [0u8; 512];
    let (n, _from) = timeout(
        Duration::from_secs(1),
        remote_candidate.recv_from(&mut probe_buf),
    )
    .await
    .unwrap()
    .unwrap();
    let probe = decode_authenticated_punch_packet(&probe_buf[..n], &key).unwrap();

    let peer_reflexive = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_reflexive_addr = peer_reflexive.local_addr().unwrap();
    let ack = build_authenticated_punch_ack(probe.nonce, "peer-b", "peer-a", 11, &key);
    peer_reflexive.send_to(&ack, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("peer-b").await.unwrap();
            if conn.endpoint == Some(peer_reflexive_addr)
                && conn.state == ConnectionState::HolePunching
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(peer_reflexive_addr));
    assert!(conn.candidates.contains(&peer_reflexive_addr.to_string()));
    assert_eq!(conn.state, ConnectionState::HolePunching);
    assert_eq!(conn.active_path(), None);

    worker.abort();
}

#[tokio::test]
async fn udp_inbound_decrypts_and_writes_packet_to_tun() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-a", "10.20.0.1", None)).await;

    let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.2");
    let (mut dataplane, _outbound_rx, inbound_tx) =
        DataPlane::new_bidirectional(tun, peers.clone());
    let dataplane_worker = tokio::spawn(async move { dataplane.run().await });

    let (mut node_a_session, node_b_session) = establish_sessions();
    let (wireguard, _encrypted_rx) = WireGuardTransport::new();
    wireguard.add_session("peer-a", node_b_session).await;
    let (udp_inbound_tx, udp_inbound_rx) = mpsc::channel(4);
    let wireguard_worker = {
        let wireguard = wireguard.clone();
        let peers = peers.clone();
        tokio::spawn(async move {
            wireguard
                .run_inbound_with_peers(udp_inbound_rx, inbound_tx, Some(peers))
                .await
        })
    };

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let udp_worker = tokio::spawn(udp.run_inbound(udp_inbound_tx));

    let ip_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"ping",
    );
    let wire_bytes = node_a_session.encrypt_to_bytes(&ip_packet).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&wire_bytes, udp_addr).await.unwrap();

    let written = timeout(Duration::from_secs(1), ctrl.recv_written())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(written, ip_packet);

    let conn = peers.get_connection("peer-a").await.unwrap();
    assert_eq!(conn.bytes_received, written.len() as u64);
    assert_eq!(conn.state.to_string(), "direct");
    assert_eq!(conn.endpoint, Some(sender.local_addr().unwrap()));
    assert_eq!(
        conn.candidate_sources
            .get(&sender.local_addr().unwrap().to_string()),
        Some(&crate::peer::CandidatePairSource::PeerReflexive)
    );

    udp_worker.abort();
    wireguard_worker.abort();
    dataplane_worker.abort();
}
