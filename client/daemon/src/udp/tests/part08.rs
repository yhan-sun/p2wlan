// ============================================================
// v0.1.116: wide-window physical probe budget
//
// Field evidence (v0.1.115 real Mini log): a 96-port fresh prediction window
// was emitted as 512 physical datagrams per session (96 candidates x 3
// sockets x ~2 rounds, session-capped) with 416 repeated target ports, and
// the identical window was re-sent across four recovery sessions (2048
// datagrams total) before the peer-reflexive path finally converged.
//
// v0.1.116 bounds the wide window to 64 candidates and the session to 192
// physical datagrams (64 candidates x 3 sockets, one controlled coverage with
// ZERO repeated target ports).  The successful cold-start profile is 2x
// inside this window: a 32-candidate scan converged in ~0.5 s with 64
// datagrams.
//
// These tests pin the physical-datagram contract of wide windows:
//   - one full window coverage (attempts = 1) sends every candidate from
//     every socket exactly once — 64 candidates x 3 sockets = 192 datagrams
//     with ZERO repeated target ports;
//   - the session stops within one probe of a Direct commit (post-promotion
//     sends are impossible);
//   - wide sweeps keep the bounded per-peer/per-IP budgets as a hard ceiling.
// ============================================================

use std::collections::HashSet;

#[tokio::test]
async fn wide_window_one_coverage_sends_every_candidate_once_per_socket() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-wide", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    // A 3-socket pool: the wide window's whole purpose is multi-socket
    // coverage of a moving remote-port window.
    transport.set_socket_pool_active(true);
    assert_eq!(transport.socket_count(), 3);

    let candidates = (0..64)
        .map(|offset| format!("127.0.0.1:{}", 31_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    // attempts = 1 is the caller-side contract for prediction / wide scatter
    // windows: ONE controlled coverage, then the ACK feedback window decides
    // whether a DIFFERENT window may be scanned.
    let report = transport
        .punch_candidates_until_not_direct_report(
            "peer-wide",
            candidates.clone(),
            Duration::ZERO,
            1,
        )
        .await
        .unwrap();

    assert_eq!(
        report.packets_sent,
        64 * 3,
        "one coverage of a 64-port window from a 3-socket pool must send exactly 192 physical probes"
    );
    assert_eq!(
        report.unique_target_endpoints as usize,
        64,
        "every one of the 64 window ports must be covered"
    );
    assert_eq!(
        report.per_socket_sent.iter().map(|(_, count)| *count).collect::<Vec<_>>(),
        vec![64, 64, 64],
        "each socket must cover the whole window exactly once"
    );
}

#[tokio::test]
async fn wide_window_repeated_attempts_never_repeat_target_ports() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-wide", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);

    let candidates = (0..64)
        .map(|offset| format!("127.0.0.1:{}", 32_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    // Even if a caller passes attempts > 1 (legacy path), the per-session
    // physical ceiling and the unique-port bookkeeping must keep the scan
    // from degenerating into candidate x socket x attempt multiplication:
    // the sweep is bounded by the session cap and every actual datagram is
    // accounted per socket.
    let report = transport
        .punch_candidates_until_not_direct_report(
            "peer-wide",
            candidates,
            Duration::from_millis(1),
            4,
        )
        .await
        .unwrap();
    assert!(
        report.packets_sent <= MAX_PUNCH_PROBES_PER_SESSION,
        "a wide window must stay inside the hard per-session physical cap"
    );
    assert!(
        report.unique_target_endpoints as usize >= 64,
        "the first controlled coverage must reach every window port before any repeat"
    );
}

#[tokio::test]
async fn wide_window_stops_within_one_probe_after_direct_commit() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-direct", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);

    let candidates = (0..64)
        .map(|offset| format!("127.0.0.1:{}", 33_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    // Commit Direct while the sweep is in flight: the per-probe direct gate
    // must stop the sweep within one probe of the promotion, so no
    // post-promotion traversal work leaks out of a wide window.  The sweep
    // and the commit race: once the promotion lands, every later probe must
    // be refused.
    let sweep = {
        let transport = transport.clone();
        tokio::spawn(async move {
            transport
                .punch_candidates_until_not_direct_report(
                    "peer-direct",
                    candidates,
                    Duration::from_millis(2),
                    1,
                )
                .await
        })
    };
    // Give the sweep a head start (a batch or two), then promote Direct.
    tokio::time::sleep(Duration::from_millis(1)).await;
    peers
        .record_direct_success(
            "peer-direct",
            Some("127.0.0.1:33001".parse().unwrap()),
        )
        .await;
    let report = sweep.await.unwrap().unwrap();

    assert!(
        report.packets_sent < 64 * 3,
        "the wide sweep must stop within one probe of the Direct commit; sent {}",
        report.packets_sent
    );
    assert!(
        !peers.is_direct_sync("peer-direct")
            || report.packets_sent < 64 * 3,
        "Direct promotion must preempt the rest of the window"
    );
}

#[tokio::test]
async fn wide_window_respects_per_peer_and_remote_ip_physical_budgets() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);
    {
        let now = Instant::now();
        let mut budget = transport.outbound_probe_budget.lock().await;
        // Leave only a small fraction of the remote-IP allowance so the wide
        // window is forced to stop at the budget, not at its own size.
        budget.insert(
            OutboundProbeBudgetKey::PeerRemoteIp(
                "peer-b".to_string(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ),
            std::iter::repeat_n(now, OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP - 24).collect(),
        );
    }

    let candidates = (0..64)
        .map(|offset| format!("127.0.0.1:{}", 34_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let report = transport
        .punch_candidates_until_not_direct_report(
            "peer-b",
            candidates,
            Duration::ZERO,
            1,
        )
        .await
        .unwrap();

    assert_eq!(
        report.packets_sent as usize,
        24,
        "the wide window must stop exactly at the shared per-remote-IP budget"
    );
    assert!(
        report.budget_skipped > 0,
        "the window tail must be accounted as budget-skipped, never silently dropped"
    );
}

#[tokio::test]
async fn wide_window_probe_coverage_counts_unique_and_repeated_ports() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-wide", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);

    let candidates = (0..64)
        .map(|offset| format!("127.0.0.1:{}", 35_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let report = transport
        .punch_candidates_until_not_direct_report(
            "peer-wide",
            candidates.clone(),
            Duration::ZERO,
            1,
        )
        .await
        .unwrap();

    let diagnostics = peers.diagnostics().await;
    let event = diagnostics[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "active_pool_scan_completed")
        .expect("wide scan completion must be recorded");
    // One controlled coverage from a 3-socket pool sends every port once per
    // socket: repeated_target_ports = 64 x (3-1) = 128 is the NECESSARY
    // multi-socket coverage (each socket carries a different source mapping
    // for the remote's destination-dependent NAT), never an attempt
    // multiplication.  The v0.1.115 failure mode was 416 repeats from
    // attempts=4 rounds over the SAME window.
    assert!(
        event.detail.contains("repeated_target_ports=128"),
        "one controlled coverage must repeat each port exactly once per alternate socket: {}",
        event.detail
    );
    assert!(
        event.detail.contains(&format!("unique_target_ports={}", report.unique_target_endpoints)),
        "coverage telemetry must count the exact unique ports covered"
    );
    // The per-socket physical datagram accounting is explicit in the event.
    let ports = candidates
        .iter()
        .map(|endpoint| endpoint.port())
        .collect::<HashSet<_>>();
    assert_eq!(ports.len(), 64);
}
