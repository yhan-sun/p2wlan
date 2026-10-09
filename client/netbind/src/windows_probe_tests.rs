use super::*;
use std::time::Duration;
use windows_sys::Win32::Networking::WinSock::{
    IPPROTO_IP, IPPROTO_IPV6, IPV6_DONTFRAG, IPV6_MTU_DISCOVER, IP_DONTFRAGMENT, IP_MTU_DISCOVER,
    IP_PMTUDISC_DO, IP_PMTUDISC_PROBE, WSAEMSGSIZE,
};

#[tokio::test]
async fn windows_probe_profile_rejects_cached_path_mtu_modes_without_repairing_socket() {
    for (address, level, discover, dontfrag) in [
        ("127.0.0.1:0", IPPROTO_IP, IP_MTU_DISCOVER, IP_DONTFRAGMENT),
        ("[::1]:0", IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_DONTFRAG),
    ] {
        let socket = bind_udp(address.parse().unwrap(), None).await.unwrap();
        let destination = socket.local_addr().unwrap().ip();
        assert_eq!(
            read_windows_option(&socket, level, discover),
            Some(IP_PMTUDISC_PROBE),
        );
        assert!(udp_no_fragment_supported(&socket, destination));

        // DO retains DF but lets a cached PMTU block probes. The old
        // DF-only capability check incorrectly accepted this socket.
        assert!(set_and_verify_windows_option(&socket, level, dontfrag, 1));
        assert!(set_and_verify_windows_option(
            &socket,
            level,
            discover,
            IP_PMTUDISC_DO,
        ));
        assert_eq!(read_windows_option(&socket, level, dontfrag), Some(1));
        for _ in 0..2 {
            assert!(!udp_no_fragment_supported(&socket, destination));
            assert_eq!(
                read_windows_option(&socket, level, discover),
                Some(IP_PMTUDISC_DO),
                "capability reads must not mutate a live socket",
            );
        }
    }
}

#[tokio::test]
async fn windows_probe_profile_sends_probes_after_a_local_size_rejection() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let sender = bind_udp(address.parse().unwrap(), None).await.unwrap();
        let receiver = bind_udp(address.parse().unwrap(), None).await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let oversized = vec![0u8; 65_536];
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            sender.send_to(&oversized, destination),
        )
        .await
        .expect("oversized send must finish")
        .expect_err("oversized UDP datagram must be rejected locally");
        assert_eq!(error.raw_os_error(), Some(WSAEMSGSIZE));

        for size in [1200, 1464, 1472, 1200] {
            let payload = vec![0x5au8; size];
            tokio::time::timeout(Duration::from_secs(2), async {
                assert_eq!(sender.send_to(&payload, destination).await.unwrap(), size);
                let mut received = vec![0u8; 2048];
                let (length, source) = receiver.recv_from(&mut received).await.unwrap();
                assert_eq!(source, sender.local_addr().unwrap());
                assert_eq!(&received[..length], payload.as_slice());
            })
            .await
            .expect("probe round trip must finish");
            assert!(udp_no_fragment_supported(&sender, destination.ip()));
        }
    }
}
