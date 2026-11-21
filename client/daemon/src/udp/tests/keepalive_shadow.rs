/// The existing silent UDP consent fixture plus actual business selection.
/// This is an observation/regression only: no path policy or miss threshold
/// changes, and no canonical encrypted application-delivery claim.
#[tokio::test]
async fn c02_original_udp_first_and_second_miss_keep_actual_business_direct() {
    use futures_util::FutureExt;

    // Reuse the existing matching-consent fixture's two-second bound and
    // reserve its last second inside that same end for original task cleanup.
    let end = tokio::time::Instant::now() + Duration::from_secs(2);
    let work_end = end - Duration::from_secs(1);
    let peers = peer_manager();
    let burst_owner = Arc::new(ProbeBurstCaptureForTest::new());
    // Keep every successfully acquired socket outside the timed body. A
    // partial setup must use the same cleanup as a completed consent round.
    let mut remote_owner = None;
    let mut udp_owner = None;
    let mut remote_addr = None;
    let mut local_addr = None;
    let mut primary = None;
    let mut ipv6 = None;

    let body = std::panic::AssertUnwindSafe(async {
        remote_owner = Some(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?,
        );
        let remote = remote_owner.as_ref().unwrap();
        let endpoint = remote.local_addr().map_err(|e| e.to_string())?;
        remote_addr = Some(endpoint);
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(endpoint)))
            .await;
        peers
            .record_direct_probe_success_with_latency(
                "peer-b",
                endpoint,
                Some(Duration::from_millis(5)),
            )
            .await;
        peers.record_direct_success("peer-b", Some(endpoint)).await;
        udp_owner = Some(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
                .await
                .map_err(|e| e.to_string())?,
        );
        let udp = udp_owner.as_mut().unwrap();
        udp.probe_burst_capture_for_test = Some(burst_owner.clone());
        primary = Some(Arc::downgrade(&udp.socket));
        ipv6 = udp.ipv6_socket.as_ref().map(Arc::downgrade);
        let source_endpoint = udp.local_addr().map_err(|e| e.to_string())?;
        local_addr = Some(source_endpoint);

        let mut observed = Vec::with_capacity(3);
        let mut received_nonces = HashSet::new();
        for miss in 1_u32..=3 {
            // Original silent consent test uses a10ms ACK wait. The real
            // sender and its unchanged25/75ms reliability bursts still run.
            udp.run_keepalive_round(Duration::from_millis(10)).await;
            let mut fresh = false;
            for _ in 0..9 {
                let mut bytes = [0u8; 512];
                let (len, source) = remote
                    .recv_from(&mut bytes)
                    .await
                    .map_err(|e| e.to_string())?;
                let probe =
                    decode_punch_packet(&bytes[..len]).ok_or("invalid actual consent packet")?;
                if source != source_endpoint || probe.kind != PunchPacketKind::Punch {
                    return Err("actual consent source/kind mismatch".to_string());
                }
                if received_nonces.insert(probe.nonce) {
                    fresh = true;
                    break;
                }
            }
            if !fresh {
                return Err("no distinct actual consent request within fixed wire cap".to_string());
            }
            let connection = peers
                .get_connection("peer-b")
                .await
                .ok_or("missing original peer")?;
            let pair = connection
                .candidate_pairs
                .iter()
                .find(|pair| pair.remote_endpoint == endpoint)
                .ok_or("missing original consent pair")?;
            let selection = peers.select_path_for_data("peer-b", true, false).await;
            observed.push((
                miss,
                connection.state,
                connection.direct_health.consecutive_failures,
                pair.state,
                selection.path,
                selection.direct_confirmed,
                pair.consecutive_failures,
                pair.failure_count,
            ));
        }
        Ok::<_, String>(observed)
    })
    .catch_unwind();
    let body_result = tokio::time::timeout_at(work_end, body).await;
    let (actual_burst_handles, bursts_joined) = burst_owner.abort_and_join_until(end).await;
    let had_udp = udp_owner.is_some();
    let had_remote = remote_owner.is_some();
    drop(udp_owner.take());
    drop(remote_owner.take());
    let original_sockets_released = primary.is_none_or(|socket| socket.upgrade().is_none())
        && ipv6.is_none_or(|socket| socket.upgrade().is_none());
    let local_rebound = if let Some(address) = local_addr {
        Some(tokio::time::timeout_at(end, UdpSocket::bind(address)).await)
    } else {
        None
    };
    let remote_rebound = if let Some(address) = remote_addr {
        Some(tokio::time::timeout_at(end, UdpSocket::bind(address)).await)
    } else {
        None
    };
    let ports_reclaimed = (!had_udp || matches!(&local_rebound, Some(Ok(Ok(_)))))
        && (!had_remote || matches!(&remote_rebound, Some(Ok(Ok(_)))));
    drop(local_rebound);
    drop(remote_rebound);

    assert!(
        bursts_joined,
        "original consent burst handle not joined before original end"
    );
    assert!(
        original_sockets_released && ports_reclaimed,
        "original consent sockets not reclaimed before assertions"
    );
    let observed = match body_result {
        Ok(Ok(Ok(value))) => value,
        Ok(Ok(Err(error))) => panic!("actual consent fixture failed after cleanup: {error}"),
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("actual consent fixture exceeded original work end after cleanup"),
    };
    assert_eq!(
        actual_burst_handles, 3,
        "this original legacy fixture must retain exactly its three producer handles"
    );
    for row in &observed {
        assert_eq!(row.6, row.0, "every real missed consent remains recorded");
        assert_eq!(row.7, u64::from(row.0));
    }
    for row in &observed[..2] {
        assert_eq!(row.1, ConnectionState::Direct);
        assert_eq!(row.2, row.0);
        assert_eq!(
            row.4,
            Some(crate::peer::NetworkPath::Direct),
            "C02 business selector must retain original Direct after miss{}; pair={:?}",
            row.0,
            row.3
        );
        assert!(row.5);
        assert_eq!(row.3, crate::peer::CandidatePairState::Selected);
    }
    assert_eq!(observed[2].1, ConnectionState::FallbackToRelay);
    assert_eq!(observed[2].2, 3);
    assert_eq!(observed[2].3, crate::peer::CandidatePairState::Degraded);
    assert_eq!(observed[2].4, None);
    assert!(!observed[2].5);
}
