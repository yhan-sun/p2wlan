//! Original PeerManager sequence ownership after real lifecycle operations.
//! These are owner regressions, not physical Full or native ACK fixtures.

use super::*;
use std::future::Future;
use tokio::net::UdpSocket;
use tokio::time::{timeout_at, Instant as TokioInstant};

async fn bounded<F: Future>(end: TokioInstant, future: F) -> F::Output {
    timeout_at(
        end.min(TokioInstant::now() + Duration::from_secs(1)),
        future,
    )
    .await
    .expect("original sequence-owner operation exceeded fixed budget")
}

fn sequence_peer(node: &str, endpoint: SocketAddr) -> PeerInfo {
    let mut peer = test_peer(node, endpoint);
    peer.public_key = hex::encode(NodeIdentity::generate().public_key());
    peer
}

async fn host_candidates(
    peers: &PeerManager,
    node: &str,
    endpoint: SocketAddr,
    revision: u64,
    end: TokioInstant,
) {
    // The original publication copies prefixes into currently live peers.
    // Install it after each add/re-add, before classifying the Host pair.
    bounded(
        end,
        peers
            .set_local_interface_networks(vec![LocalNetwork::new("127.0.0.1".parse().unwrap(), 8)]),
    )
    .await;
    let candidate = endpoint.to_string();
    assert_eq!(
        bounded(
            end,
            peers.add_candidates_with_metadata(
                node,
                std::slice::from_ref(&candidate),
                &HashMap::from([(candidate.clone(), "host".to_string())]),
                revision,
                None,
            ),
        )
        .await,
        CandidateSetApplyResult::Applied
    );
}

async fn original_lan_commit(
    peers: &PeerManager,
    node: &str,
    endpoint: SocketAddr,
    local: SocketAddr,
    end: TokioInstant,
) -> ActivePathSnapshot {
    bounded(
        end,
        peers.record_direct_probe_success_with_latency_and_local_endpoint(
            node,
            endpoint,
            Some(Duration::from_millis(1)),
            Some(local),
        ),
    )
    .await;
    bounded(
        end,
        peers.record_direct_success_with_local_endpoint(node, Some(endpoint), Some(local)),
    )
    .await;
    let snapshot = bounded(
        end,
        peers.active_direct_path_snapshot(node, peers.current_network_generation_sync(), true),
    )
    .await;
    let conn = bounded(end, peers.get_connection(node)).await.unwrap();
    assert!(
        snapshot.is_some(),
        "original LAN admission missing: state={:?} online={} direct_g={} current_g={} local_networks={:?} sources={:?} pairs={:?} health={:?}",
        conn.state,
        conn.online,
        conn.direct_generation,
        peers.current_network_generation_sync(),
        conn.local_interface_networks,
        conn.candidate_sources,
        conn.candidate_pairs,
        conn.direct_health,
    );
    let snapshot = snapshot.unwrap();
    assert!(peers.active_direct_path_snapshot_is_current_sync(node, snapshot));
    assert_eq!(conn.direct_commit_seq, snapshot.direct_commit_seq);
    assert_eq!(
        peers.direct_commit_seq_sync(node),
        Some(snapshot.direct_commit_seq)
    );
    snapshot
}

async fn current_sequence(peers: &PeerManager, node: &str, end: TokioInstant) -> u64 {
    let actual = bounded(end, peers.get_connection(node))
        .await
        .unwrap()
        .direct_commit_seq;
    assert_eq!(peers.direct_commit_seq_sync(node), Some(actual));
    actual
}

async fn consent_target(peers: &PeerManager, node: &str) -> DirectConsentPath {
    peers
        .direct_consent_targets()
        .await
        .into_iter()
        .find(|(peer, _)| peer == node)
        .expect("selected consent target")
        .1
}

async fn assert_stale_consent(
    peers: &PeerManager,
    node: &str,
    old: DirectConsentPath,
    local: SocketAddr,
) {
    assert!(
        !peers
            .record_direct_consent_timeout(node, old, Some(local))
            .await
    );
    assert_eq!(
        peers
            .get_connection(node)
            .await
            .unwrap()
            .direct_health
            .consecutive_failures,
        0
    );
}

#[tokio::test]
async fn repeated_port_changes_challenge_only_the_latest_source_after_cooldown() {
    let end = TokioInstant::now() + Duration::from_secs(3);
    let local = "127.0.0.1:47000".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:48000".parse().unwrap();
    let peers = PeerManager::new(test_config());
    let node = "repeated-port-change";
    peers.add_peer(&sequence_peer(node, remote)).await;
    host_candidates(&peers, node, remote, 5, end).await;
    let active = original_lan_commit(&peers, node, remote, local, end).await;
    let mut locks = peers.connections.write().await;
    let conn = locks.get_mut(node).unwrap();
    let now = Instant::now();
    let endpoint = |port| SocketAddr::new(remote.ip(), port);
    let mut observe = |port, seconds_ago| {
        let source = endpoint(port);
        conn.observe_direct_source(
            active.generation,
            Some(active.peer_session_generation),
            local,
            source,
            now - Duration::from_secs(seconds_ago),
        );
        conn.may_validate_alternate(active.generation, source)
    };

    observe(48001, 12); // Stable asymmetric baseline.
    observe(48002, 10); // Starts the eight-second budget window.
    assert!(!observe(48003, 7));
    assert!(!observe(48004, 5));
    assert!(!observe(48004, 3));
    assert!(observe(48004, 2)); // Same source, now at the budget boundary.
    assert!(!conn.may_validate_alternate(active.generation, endpoint(48002)));
    assert!(!conn.may_validate_alternate(active.generation, endpoint(48003)));
    assert_eq!(
        conn.direct_consent_path(active.generation).unwrap().path,
        active
    );
}

#[tokio::test]
async fn authenticated_port_change_is_bound_to_the_original_socket_and_peer() {
    let end = TokioInstant::now() + Duration::from_secs(3);
    let local = "127.0.0.1:47000".parse().unwrap();
    let remote = "127.0.0.1:48000".parse().unwrap();
    let first = "127.0.0.1:48001".parse().unwrap();
    let moved = "127.0.0.1:48002".parse().unwrap();
    let peers = PeerManager::new(test_config());
    let node = "port-change";
    peers.add_peer(&sequence_peer(node, remote)).await;
    host_candidates(&peers, node, remote, 5, end).await;
    let active = original_lan_commit(&peers, node, remote, local, end).await;
    let mut locks = peers.connections.write().await;
    let conn = locks.get_mut(node).unwrap();
    let now = Instant::now();
    let life = Some(active.peer_session_generation);
    let start = now - Duration::from_secs(5);
    conn.observe_direct_source(active.generation, life, local, first, start);
    conn.observe_direct_source(
        active.generation,
        life,
        local,
        first,
        start + Duration::from_secs(1),
    );
    assert!(!conn.may_validate_alternate(active.generation, first));
    conn.observe_direct_source(active.generation + 1, life, local, moved, now);
    conn.observe_direct_source(active.generation, None, local, moved, now);
    conn.observe_direct_source(active.generation, life, remote, moved, now);
    assert!(!conn.may_validate_alternate(active.generation, moved));
    conn.observe_direct_source(active.generation, life, local, moved, now);
    assert!(conn.may_validate_alternate(active.generation, moved));
    assert!(!conn.may_validate_alternate(active.generation + 1, moved));
    conn.observe_direct_source(active.generation, life, local, first, start);
    assert!(conn.may_validate_alternate(active.generation, moved));
    assert_eq!(
        conn.selected_direct_endpoint_for_consent(active.generation),
        Some(remote)
    );
}

#[tokio::test]
async fn b28_original_direct_sequence_survives_remove_readd_without_resurrecting_snapshot() {
    let end = TokioInstant::now() + Duration::from_secs(3);
    let local = bounded(end, UdpSocket::bind("127.0.0.1:0")).await.unwrap();
    let remote = bounded(end, UdpSocket::bind("127.0.0.1:0")).await.unwrap();
    let local_endpoint = local.local_addr().unwrap();
    let remote_endpoint = remote.local_addr().unwrap();
    let peers = PeerManager::new(test_config());
    let peer = sequence_peer("b28-sequence-readd", remote_endpoint);
    bounded(end, peers.add_peer(&peer)).await;
    host_candidates(&peers, &peer.node_id, remote_endpoint, 10, end).await;
    let original =
        original_lan_commit(&peers, &peer.node_id, remote_endpoint, local_endpoint, end).await;

    let old_consent = consent_target(&peers, &peer.node_id).await;
    bounded(end, peers.remove_peer(&peer.node_id)).await;
    assert!(bounded(end, peers.get_connection(&peer.node_id))
        .await
        .is_none());
    assert_eq!(
        peers.direct_commit_seq_sync(&peer.node_id),
        Some(original.direct_commit_seq)
    );
    assert!(!peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, original));
    bounded(end, peers.add_peer(&peer)).await;
    assert_eq!(
        current_sequence(&peers, &peer.node_id, end).await,
        original.direct_commit_seq
    );
    assert_ne!(
        peers.peer_session_generation_sync(&peer.node_id),
        Some(original.peer_session_generation)
    );
    assert!(!peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, original));

    host_candidates(&peers, &peer.node_id, remote_endpoint, 11, end).await;
    let current =
        original_lan_commit(&peers, &peer.node_id, remote_endpoint, local_endpoint, end).await;
    assert_stale_consent(&peers, &peer.node_id, old_consent, local_endpoint).await;
    assert!(current.direct_commit_seq > original.direct_commit_seq);
    assert_ne!(
        current.peer_session_generation,
        original.peer_session_generation
    );
    assert!(!peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, original));
    assert!(peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, current));

    // An ordinary update of an existing owner must not reinitialize its sequence.
    let mut update = peer.clone();
    update.last_seen = 1;
    bounded(end, peers.add_peer(&update)).await;
    assert_eq!(
        current_sequence(&peers, &peer.node_id, end).await,
        current.direct_commit_seq
    );
    let duplicate =
        original_lan_commit(&peers, &peer.node_id, remote_endpoint, local_endpoint, end).await;
    assert_eq!(duplicate.direct_commit_seq, current.direct_commit_seq);
    assert!(peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, current));
}

#[tokio::test]
async fn b28_original_direct_sequence_readd_then_candidate_handover_keeps_one_owner() {
    let end = TokioInstant::now() + Duration::from_secs(3);
    let local = bounded(end, UdpSocket::bind("127.0.0.1:0")).await.unwrap();
    let old_remote = bounded(end, UdpSocket::bind("127.0.0.1:0")).await.unwrap();
    let new_remote = bounded(end, UdpSocket::bind("127.0.0.1:0")).await.unwrap();
    let local_endpoint = local.local_addr().unwrap();
    let old_endpoint = old_remote.local_addr().unwrap();
    let new_endpoint = new_remote.local_addr().unwrap();
    assert_ne!(old_endpoint, new_endpoint);
    let peers = PeerManager::new(test_config());
    let peer = sequence_peer("b28-sequence-handover", old_endpoint);
    bounded(end, peers.add_peer(&peer)).await;
    host_candidates(&peers, &peer.node_id, old_endpoint, 10, end).await;
    let removed =
        original_lan_commit(&peers, &peer.node_id, old_endpoint, local_endpoint, end).await;
    bounded(end, peers.remove_peer(&peer.node_id)).await;
    bounded(end, peers.add_peer(&peer)).await;
    assert_eq!(
        current_sequence(&peers, &peer.node_id, end).await,
        removed.direct_commit_seq
    );
    host_candidates(&peers, &peer.node_id, old_endpoint, 11, end).await;
    let before =
        original_lan_commit(&peers, &peer.node_id, old_endpoint, local_endpoint, end).await;

    let old_consent = consent_target(&peers, &peer.node_id).await;

    // The original exact-path failure removes Direct proof. A changed signaled
    // set can now perform a real handover rather than retain the healthy path.
    assert!(
        bounded(
            end,
            peers.record_direct_failure_for_active_path_snapshot(
                &peer.node_id,
                before,
                REASON_DIRECT_PROBE_FAILED,
                "original sequence regression path failure",
                Some(local_endpoint),
            ),
        )
        .await
    );
    assert!(!peers.is_direct_sync(&peer.node_id));
    assert_eq!(
        current_sequence(&peers, &peer.node_id, end).await,
        before.direct_commit_seq
    );
    let old_epoch = bounded(end, peers.current_remote_candidate_epoch(&peer.node_id))
        .await
        .unwrap();
    host_candidates(&peers, &peer.node_id, new_endpoint, 12, end).await;
    let new_epoch = bounded(end, peers.current_remote_candidate_epoch(&peer.node_id))
        .await
        .unwrap();
    assert!(new_epoch > old_epoch);
    assert_eq!(
        current_sequence(&peers, &peer.node_id, end).await,
        before.direct_commit_seq + 1
    );
    assert!(!peers.is_direct_sync(&peer.node_id));
    assert!(!peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, before));

    let after = original_lan_commit(&peers, &peer.node_id, new_endpoint, local_endpoint, end).await;
    assert_stale_consent(&peers, &peer.node_id, old_consent, local_endpoint).await;
    assert_eq!(after.generation, before.generation);
    assert_eq!(
        after.peer_session_generation,
        before.peer_session_generation
    );
    assert!(peers.is_direct_sync(&peer.node_id));
    assert!(after.direct_commit_seq > before.direct_commit_seq);
    assert!(!peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, before));
    assert!(peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, after));

    // Freshness alone is not a transport change and must not bump the sequence.
    host_candidates(&peers, &peer.node_id, new_endpoint, 13, end).await;
    assert_eq!(
        current_sequence(&peers, &peer.node_id, end).await,
        after.direct_commit_seq
    );
    assert!(peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, after));
    assert!(!peers.active_direct_path_snapshot_is_current_sync(&peer.node_id, removed));
}

#[tokio::test]
async fn additive_candidate_offer_keeps_epoch_only_for_same_identity_and_sources() {
    let mut config = test_config();
    config.network.early_candidate_signaling = true;
    let peers = PeerManager::new(config);
    let a = "203.0.113.7:1001".to_owned();
    let b = "203.0.113.7:1002".to_owned();
    let peer = sequence_peer("additive", a.parse().unwrap());
    peers.add_peer(&peer).await;
    let revision = |boot: u64, seq| 0x4000_0000_0000_0000 | (boot << 21) | seq;
    let mut sources = HashMap::from([
        (a.clone(), "stun_observed".into()),
        (b.clone(), "stun_observed".into()),
    ]);
    let apply = |rev, endpoints: Vec<String>, labels: HashMap<String, String>| {
        let peers = &peers;
        let peer = &peer;
        async move {
            assert_eq!(
                peers
                    .add_candidates_with_metadata_for_identity(
                        &peer.node_id,
                        &endpoints,
                        &labels,
                        rev,
                        None,
                        Some(&peer.public_key)
                    )
                    .await,
                CandidateSetApplyResult::Applied
            );
            peers
                .current_remote_candidate_epoch(&peer.node_id)
                .await
                .unwrap()
        }
    };
    let initial = apply(revision(7, 1u64), vec![a.clone()], sources.clone()).await;
    assert_eq!(
        apply(revision(7, 2), vec![a.clone(), b.clone()], sources.clone()).await,
        initial
    );
    let withdrawn = apply(revision(7, 3), vec![a.clone()], sources.clone()).await;
    assert!(withdrawn > initial);
    sources.insert(a.clone(), "predicted".into());
    let changed_source = apply(revision(7, 4), vec![a.clone(), b.clone()], sources.clone()).await;
    assert!(changed_source > withdrawn);
    let fresh = apply(revision(8, 1), vec![a], sources).await;
    assert!(fresh > changed_source);
}
