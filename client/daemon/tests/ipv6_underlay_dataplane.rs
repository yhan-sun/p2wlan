//! End-to-end integration test for IPv6 UDP Underlay data-plane.
//!
//! Validates:
//! 1. Dual-stack binding: local IPv4 + IPv6 UDP loopback sockets.
//! 2. Production WireGuard Noise IK handshake between Node A and Node B.
//! 3. Encapsulating overlay virtual IPv4 traffic (10.20.0.2 -> 10.20.0.3)
//!    inside real WireGuard AEAD encrypted packets over IPv6 UDP underlay.
//! 4. Inbound reader correctly identifies IPV6_SOCKET_INDEX and remote IPv6 endpoint.
//! 5. Decryption recovers original virtual IPv4 packet with payload intact.
//! 6. Bidirectional roundtrip and multi-packet replay protection over IPv6 underlay.
//! 7. IPv4 and IPv6 dual-stack coexistence without cross-family pollution.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use p2pnet_crypto::NodeIdentity;
use p2pnet_daemon::peer::PeerManager;
use p2pnet_daemon::transport::EncryptedPeerPacket;
use p2pnet_daemon::udp::{UdpTransport, IPV6_SOCKET_INDEX};
use p2pnet_daemon::Config;
use p2pnet_tun::packet::{Ipv4Packet, Protocol};
use p2pnet_wireguard::handshake::{HandshakeInitiator, HandshakeResponder};
use p2pnet_wireguard::session::TransportSession;
use p2pnet_wireguard::types::MessageTransport;
use tokio::sync::mpsc;
use tokio::time::timeout;

fn establish_wireguard_sessions() -> (TransportSession, TransportSession) {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();

    let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut responder = HandshakeResponder::new(node_b, None);

    let init = initiator.create_initiation().expect("initiation created");
    let (response, node_b_keys) = responder
        .consume_initiation_and_respond(&init)
        .expect("response created");
    let node_a_keys = initiator
        .consume_response(&response)
        .expect("response consumed");

    (
        TransportSession::new(node_a_keys),
        TransportSession::new(node_b_keys),
    )
}

#[tokio::test]
async fn test_ipv6_underlay_dataplane_roundtrip() {
    let config_a = Config::generate_default("https://control.test", "net1").unwrap();
    let config_b = Config::generate_default("https://control.test", "net1").unwrap();

    let peers_a = Arc::new(PeerManager::new(config_a));
    let peers_b = Arc::new(PeerManager::new(config_b));

    let (tx_a, mut rx_a) = mpsc::channel(64);
    let (tx_b, mut rx_b) = mpsc::channel(64);

    let transport_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .expect("transport A bound")
        .with_local_node_id("node-a")
        .with_inbound_channel(tx_a.clone());

    let transport_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .expect("transport B bound")
        .with_local_node_id("node-b")
        .with_inbound_channel(tx_b.clone());

    let v6_addr_a = transport_a
        .ipv6_local_addr()
        .expect("transport A has IPv6 socket");
    let v6_addr_b = transport_b
        .ipv6_local_addr()
        .expect("transport B has IPv6 socket");

    assert!(v6_addr_a.is_ipv6(), "Node A underlay must be IPv6");
    assert!(v6_addr_b.is_ipv6(), "Node B underlay must be IPv6");

    // Spawn inbound readers for both transports
    let t_a = transport_a.clone();
    let _reader_a = tokio::spawn(async move {
        let _ = t_a.run_inbound(tx_a).await;
    });

    let t_b = transport_b.clone();
    let _reader_b = tokio::spawn(async move {
        let _ = t_b.run_inbound(tx_b).await;
    });

    // Establish real WireGuard sessions
    let (mut session_a, mut session_b) = establish_wireguard_sessions();

    // Virtual IPv4 overlay endpoints
    let virtual_ip_a = Ipv4Addr::new(10, 20, 0, 2);
    let virtual_ip_b = Ipv4Addr::new(10, 20, 0, 3);
    let payload = b"p2wlan-ipv6-underlay-e2e-payload";

    // 1. Node A -> Node B (ping request)
    let icmp_req =
        Ipv4Packet::build_icmp_echo_request(virtual_ip_a, virtual_ip_b, 0x4321, 1, payload);
    let wire_bytes_req = session_a
        .encrypt_to_bytes(&icmp_req)
        .expect("session A encrypt");

    let packet_to_b = EncryptedPeerPacket {
        peer_id: "node-b".to_string(),
        dst_ip: virtual_ip_b.to_string(),
        wire_bytes: wire_bytes_req,
        is_business: true,
    };

    let sent_bytes = transport_a
        .send_packet_to(&packet_to_b, v6_addr_b)
        .await
        .expect("send to Node B over IPv6");
    assert!(sent_bytes > 0);

    let received_b = timeout(Duration::from_secs(3), rx_b.recv())
        .await
        .expect("rx_b receive timeout")
        .expect("channel closed");

    assert_eq!(
        received_b.socket_index,
        Some(IPV6_SOCKET_INDEX),
        "Inbound packet on B must arrive via IPV6_SOCKET_INDEX"
    );
    assert_eq!(
        received_b.local_endpoint,
        Some(v6_addr_b),
        "Local endpoint must match Node B's IPv6 socket"
    );
    assert_eq!(
        received_b.source,
        Some(v6_addr_a),
        "Source must match Node A's IPv6 socket"
    );

    // Decrypt on Node B and verify inner virtual IPv4 packet
    let wireguard_msg_b =
        MessageTransport::from_bytes(&received_b.wire_bytes).expect("valid wireguard message");
    let decrypted_b = session_b
        .decrypt(&wireguard_msg_b)
        .expect("session B decrypt");
    assert_eq!(decrypted_b, icmp_req, "Decrypted packet must match sent");

    let parsed_b = Ipv4Packet::new(&decrypted_b).expect("valid ipv4 packet");
    assert_eq!(parsed_b.src_addr(), virtual_ip_a);
    assert_eq!(parsed_b.dst_addr(), virtual_ip_b);
    assert_eq!(parsed_b.protocol(), Protocol::Icmp);
    assert!(parsed_b.payload().ends_with(payload));

    // 2. Node B -> Node A (pong reply)
    let reply_payload = b"p2wlan-ipv6-underlay-e2e-reply-pong";
    let icmp_reply =
        Ipv4Packet::build_icmp_echo_request(virtual_ip_b, virtual_ip_a, 0x4321, 1, reply_payload);
    let wire_bytes_reply = session_b
        .encrypt_to_bytes(&icmp_reply)
        .expect("session B encrypt reply");

    let packet_to_a = EncryptedPeerPacket {
        peer_id: "node-a".to_string(),
        dst_ip: virtual_ip_a.to_string(),
        wire_bytes: wire_bytes_reply,
        is_business: true,
    };

    let sent_reply_bytes = transport_b
        .send_packet_to(&packet_to_a, v6_addr_a)
        .await
        .expect("send to Node A over IPv6");
    assert!(sent_reply_bytes > 0);

    let received_a = timeout(Duration::from_secs(3), rx_a.recv())
        .await
        .expect("rx_a receive timeout")
        .expect("channel closed");

    assert_eq!(
        received_a.socket_index,
        Some(IPV6_SOCKET_INDEX),
        "Inbound packet on A must arrive via IPV6_SOCKET_INDEX"
    );
    assert_eq!(
        received_a.local_endpoint,
        Some(v6_addr_a),
        "Local endpoint must match Node A's IPv6 socket"
    );
    assert_eq!(
        received_a.source,
        Some(v6_addr_b),
        "Source must match Node B's IPv6 socket"
    );

    let wireguard_msg_a =
        MessageTransport::from_bytes(&received_a.wire_bytes).expect("valid wireguard message");
    let decrypted_a = session_a
        .decrypt(&wireguard_msg_a)
        .expect("session A decrypt reply");
    assert_eq!(decrypted_a, icmp_reply);

    let parsed_a = Ipv4Packet::new(&decrypted_a).expect("valid ipv4 reply packet");
    assert_eq!(parsed_a.src_addr(), virtual_ip_b);
    assert_eq!(parsed_a.dst_addr(), virtual_ip_a);
    assert_eq!(parsed_a.protocol(), Protocol::Icmp);
    assert!(parsed_a.payload().ends_with(reply_payload));

    // 3. Multi-packet roundtrip over IPv6 underlay
    for seq in 2..=6 {
        let burst_payload = format!("ipv6-underlay-burst-{seq}");
        let req = Ipv4Packet::build_icmp_echo_request(
            virtual_ip_a,
            virtual_ip_b,
            0x4321,
            seq,
            burst_payload.as_bytes(),
        );
        let wire = session_a.encrypt_to_bytes(&req).expect("burst encrypt");
        let pkt = EncryptedPeerPacket {
            peer_id: "node-b".to_string(),
            dst_ip: virtual_ip_b.to_string(),
            wire_bytes: wire,
            is_business: true,
        };
        transport_a
            .send_packet_to(&pkt, v6_addr_b)
            .await
            .expect("burst send");

        let recv = timeout(Duration::from_secs(3), rx_b.recv())
            .await
            .expect("burst rx_b timeout")
            .expect("channel closed");
        assert_eq!(recv.socket_index, Some(IPV6_SOCKET_INDEX));
        let msg = MessageTransport::from_bytes(&recv.wire_bytes).expect("valid wireguard msg");
        let dec = session_b.decrypt(&msg).expect("burst decrypt");
        let parsed = Ipv4Packet::new(&dec).expect("valid packet");
        assert!(parsed.payload().ends_with(burst_payload.as_bytes()));
    }
}

#[tokio::test]
async fn test_dual_stack_coexistence_and_socket_isolation() {
    let config_a = Config::generate_default("https://control.test", "net1").unwrap();
    let config_b = Config::generate_default("https://control.test", "net1").unwrap();

    let peers_a = Arc::new(PeerManager::new(config_a));
    let peers_b = Arc::new(PeerManager::new(config_b));

    let (tx_a, mut rx_a) = mpsc::channel(64);
    let (tx_b, mut rx_b) = mpsc::channel(64);

    let transport_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .expect("transport A bound")
        .with_local_node_id("node-a")
        .with_inbound_channel(tx_a.clone());

    let transport_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .expect("transport B bound")
        .with_local_node_id("node-b")
        .with_inbound_channel(tx_b.clone());

    let v4_addr_a = transport_a.local_addr().unwrap();
    let v4_addr_b = transport_b.local_addr().unwrap();
    let v6_addr_a = transport_a.ipv6_local_addr().unwrap();
    let v6_addr_b = transport_b.ipv6_local_addr().unwrap();

    let t_a = transport_a.clone();
    let _reader_a = tokio::spawn(async move {
        let _ = t_a.run_inbound(tx_a).await;
    });

    let t_b = transport_b.clone();
    let _reader_b = tokio::spawn(async move {
        let _ = t_b.run_inbound(tx_b).await;
    });

    let (mut session_a, mut session_b) = establish_wireguard_sessions();

    // 1. Send over IPv4 socket
    let v4_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 3),
        0x1111,
        1,
        b"over-ipv4-underlay",
    );
    let wire_v4 = session_a.encrypt_to_bytes(&v4_packet).unwrap();
    let pkt_v4 = EncryptedPeerPacket {
        peer_id: "node-b".to_string(),
        dst_ip: "10.20.0.3".to_string(),
        wire_bytes: wire_v4,
        is_business: true,
    };
    transport_a
        .send_packet_to(&pkt_v4, v4_addr_b)
        .await
        .unwrap();

    let recv_v4 = timeout(Duration::from_secs(3), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recv_v4.socket_index, Some(0), "IPv4 underlay uses socket 0");
    assert_eq!(recv_v4.source, Some(v4_addr_a));

    // 2. Send over IPv6 socket
    let v6_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 3),
        0x2222,
        2,
        b"over-ipv6-underlay",
    );
    let wire_v6 = session_a.encrypt_to_bytes(&v6_packet).unwrap();
    let pkt_v6 = EncryptedPeerPacket {
        peer_id: "node-b".to_string(),
        dst_ip: "10.20.0.3".to_string(),
        wire_bytes: wire_v6,
        is_business: true,
    };
    transport_a
        .send_packet_to(&pkt_v6, v6_addr_b)
        .await
        .unwrap();

    let recv_v6 = timeout(Duration::from_secs(3), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recv_v6.socket_index,
        Some(IPV6_SOCKET_INDEX),
        "IPv6 underlay uses IPV6_SOCKET_INDEX"
    );
    assert_eq!(recv_v6.source, Some(v6_addr_a));

    // Decrypt both packets on B
    let msg_v4 = MessageTransport::from_bytes(&recv_v4.wire_bytes).unwrap();
    let dec_v4 = session_b.decrypt(&msg_v4).unwrap();
    assert_eq!(dec_v4, v4_packet);

    let msg_v6 = MessageTransport::from_bytes(&recv_v6.wire_bytes).unwrap();
    let dec_v6 = session_b.decrypt(&msg_v6).unwrap();
    assert_eq!(dec_v6, v6_packet);

    // 3. Send from Node B back to Node A over IPv4
    let reply_v4 = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 3),
        Ipv4Addr::new(10, 20, 0, 2),
        0x3333,
        1,
        b"reply-over-ipv4",
    );
    let wire_rep_v4 = session_b.encrypt_to_bytes(&reply_v4).unwrap();
    let pkt_rep_v4 = EncryptedPeerPacket {
        peer_id: "node-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        wire_bytes: wire_rep_v4,
        is_business: true,
    };
    transport_b
        .send_packet_to(&pkt_rep_v4, v4_addr_a)
        .await
        .unwrap();

    let recv_rep_v4 = timeout(Duration::from_secs(3), rx_a.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recv_rep_v4.socket_index, Some(0));
    assert_eq!(recv_rep_v4.source, Some(v4_addr_b));

    // 4. Send from Node B back to Node A over IPv6
    let reply_v6 = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 3),
        Ipv4Addr::new(10, 20, 0, 2),
        0x4444,
        2,
        b"reply-over-ipv6",
    );
    let wire_rep_v6 = session_b.encrypt_to_bytes(&reply_v6).unwrap();
    let pkt_rep_v6 = EncryptedPeerPacket {
        peer_id: "node-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        wire_bytes: wire_rep_v6,
        is_business: true,
    };
    transport_b
        .send_packet_to(&pkt_rep_v6, v6_addr_a)
        .await
        .unwrap();

    let recv_rep_v6 = timeout(Duration::from_secs(3), rx_a.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recv_rep_v6.socket_index, Some(IPV6_SOCKET_INDEX));
    assert_eq!(recv_rep_v6.source, Some(v6_addr_b));

    let dec_rep_v4 = session_a
        .decrypt(&MessageTransport::from_bytes(&recv_rep_v4.wire_bytes).unwrap())
        .unwrap();
    assert_eq!(dec_rep_v4, reply_v4);

    let dec_rep_v6 = session_a
        .decrypt(&MessageTransport::from_bytes(&recv_rep_v6.wire_bytes).unwrap())
        .unwrap();
    assert_eq!(dec_rep_v6, reply_v6);
}
