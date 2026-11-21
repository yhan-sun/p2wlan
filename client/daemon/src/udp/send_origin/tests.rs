// Separate negative factory/socket controls. No synthetic Some provenance.
use super::*;
use crate::config::Config;
use crate::transport::EncryptedPeerPacket;
use std::time::Duration;

#[tokio::test]
async fn b17_udp_synthetic_short_and_actual_wrong_family_error_leave_capture_empty() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let peers = Arc::new(crate::peer::PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let packet = EncryptedPeerPacket {
            room_authorization: None,
            peer_id: "untracked-negative".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: vec![0x17; 32],
            is_business: true,
        };
        let endpoint = "127.0.0.1:9".parse().unwrap();
        let mut short = UdpSendCapture::new();
        // Synthetic short-length guard only; no syscall/full-chain claim.
        short.record_full_success(
            &udp,
            &udp.socket,
            0,
            endpoint,
            31,
            &packet,
            Instant::now(),
            None,
            UdpSendFence::LegacyUnknown,
            None,
        );
        assert!(short.take().is_none());
        // Incomplete staged metadata must not invent a managed full fact.
        short.record_full_success(
            &udp,
            &udp.socket,
            0,
            endpoint,
            32,
            &packet,
            Instant::now(),
            Some(17),
            UdpSendFence::ManagedPublication,
            None,
        );
        assert!(short.take().is_none());
        let mut error = UdpSendCapture::new();
        let actual = udp
            .send_encrypted_packet_on_socket_until_with_origin(
                &udp.socket,
                0,
                &packet,
                "[::1]:9".parse().unwrap(),
                None,
                Some(&mut error),
            )
            .await;
        assert!(
            actual.is_err(),
            "IPv4 exact socket cannot send to IPv6 sockaddr"
        );
        assert!(
            error.take().is_none(),
            "actual Ready Err cannot mint a full fact"
        );
    })
    .await
    .unwrap();
}
