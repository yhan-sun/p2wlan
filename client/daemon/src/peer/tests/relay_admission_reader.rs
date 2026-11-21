//! Scheduling observations use the real connection/epoch locks. These
//! fixtures produce no KernelRead, Full, native credit or send permission.
use super::*;
use std::task::Poll;

const PEER: &str = "relay-admission-reader";

async fn fixture() -> (PeerManager, u64) {
    let mut config = test_config();
    config.relay.path_policy = crate::config::PathPolicy::RelayOnly;
    let peers = PeerManager::new(config);
    peers
        .add_peer(&test_peer(PEER, "198.51.100.4:41000".parse().unwrap()))
        .await;
    let generation = peers.current_network_generation_sync();
    assert!(
        peers
            .confirm_relay_peer(PEER, "relay.test:443", generation)
            .await
    );
    assert!(
        peers
            .is_data_path_admitted_for_generation(PEER, generation, true)
            .await
    );
    (peers, generation)
}

#[tokio::test]
async fn stable_relay_admission_does_not_join_the_epoch_mutex() {
    let (peers, generation) = fixture().await;
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    let future = peers.is_data_path_admitted_for_generation(PEER, generation, true);
    tokio::pin!(future);
    assert_eq!(futures_util::poll!(future.as_mut()), Poll::Ready(true));
    drop(held);
}

#[tokio::test]
async fn stable_relay_admission_shares_the_existing_connection_reader() {
    let (peers, generation) = fixture().await;
    let held = peers.connections.read().await;
    let future = peers.is_data_path_admitted_for_generation(PEER, generation, true);
    tokio::pin!(future);
    assert_eq!(futures_util::poll!(future.as_mut()), Poll::Ready(true));
    // A scheduling observation must not obstruct the real native try.
    assert!(peers.network_epoch_gate().try_lock().is_ok());
    drop(held);
}

#[tokio::test]
async fn missing_gate_initialization_still_requires_the_original_epoch_transaction() {
    let (peers, generation) = fixture().await;
    {
        let mut connections = peers.connections.write().await;
        let relay = &mut connections.get_mut(PEER).unwrap().relay_first;
        relay.gate_generation = None;
        relay.gate_started_at = None;
    }
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    let future = peers.is_data_path_admitted_for_generation(PEER, generation, true);
    tokio::pin!(future);
    assert!(futures_util::poll!(future.as_mut()).is_pending());
    assert!(peers.connections.read().await[PEER]
        .relay_first
        .gate_started_at
        .is_none());
    drop(held);
    assert!(future.await);
    let connections = peers.connections.read().await;
    assert_eq!(
        connections[PEER].relay_first.gate_generation,
        Some(generation)
    );
    assert!(connections[PEER].relay_first.gate_started_at.is_some());
}

#[tokio::test]
async fn unavailable_or_stale_relay_inputs_cannot_take_the_read_only_admission() {
    for variant in 0..8 {
        let (peers, generation) = fixture().await;
        let expected = if variant == 7 {
            generation + 1
        } else {
            generation
        };
        let available = variant != 6;
        {
            let mut connections = peers.connections.write().await;
            let conn = connections.get_mut(PEER).unwrap();
            match variant {
                0 => conn.relay_confirmed_at = None,
                1 => conn.relay_confirmed_generation = Some(generation + 1),
                2 => conn.relay_confirmed_endpoint = None,
                3 => conn.relay_confirmed_endpoint = Some(String::new()),
                4 => conn.online = false,
                5 => conn.state = ConnectionState::Closed,
                _ => {}
            }
        }
        let gate = peers.network_epoch_gate();
        let held = gate.lock().await;
        let future = peers.is_data_path_admitted_for_generation(PEER, expected, available);
        tokio::pin!(future);
        assert!(
            futures_util::poll!(future.as_mut()).is_pending(),
            "variant={variant}"
        );
        drop(held);
        assert!(!future.await, "variant={variant}");
    }
}

#[tokio::test]
async fn direct_first_pending_keeps_the_original_epoch_transaction() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.relay.path_policy = crate::config::PathPolicy::DirectFirst;
    let peers = PeerManager::new(config);
    peers
        .add_peer(&test_peer(PEER, "198.51.100.4:41000".parse().unwrap()))
        .await;
    let generation = peers.current_network_generation_sync();
    assert!(
        peers
            .confirm_relay_peer(PEER, "relay.test:443", generation)
            .await
    );
    assert!(peers.connections.read().await[PEER].direct_first_pending());
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    let future = peers.is_data_path_admitted_for_generation(PEER, generation, true);
    tokio::pin!(future);
    assert!(futures_util::poll!(future.as_mut()).is_pending());
    drop(held);
    assert!(!future.await);
    assert!(peers.connections.read().await[PEER].direct_first_pending());
}

#[tokio::test]
async fn real_connection_writer_still_excludes_the_admission_reader() {
    let (peers, generation) = fixture().await;
    let held = peers.connections.write().await;
    let future = peers.is_data_path_admitted_for_generation(PEER, generation, true);
    tokio::pin!(future);
    assert!(futures_util::poll!(future.as_mut()).is_pending());
    assert!(peers.network_epoch_gate().try_lock().is_ok());
    drop(held);
    assert!(future.await);
}

async fn settled_direct_fixture() -> (PeerManager, u64) {
    let peers = PeerManager::new(test_config());
    let remote = "127.0.0.2:41000".parse().unwrap();
    let local = "127.0.0.1:42000".parse().unwrap();
    let mut peer = test_peer(PEER, remote);
    peer.public_key = hex::encode(NodeIdentity::generate().public_key());
    peers.add_peer(&peer).await;
    peers
        .set_local_interface_networks(vec![LocalNetwork::new("127.0.0.1".parse().unwrap(), 8)])
        .await;
    let candidate = remote.to_string();
    assert_eq!(
        peers
            .add_candidates_with_metadata(
                PEER,
                std::slice::from_ref(&candidate),
                &HashMap::from([(candidate.clone(), "host".to_string())]),
                1,
                None,
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            PEER,
            remote,
            Some(Duration::from_millis(1)),
            Some(local),
        )
        .await;
    peers
        .record_direct_success_with_local_endpoint(PEER, Some(remote), Some(local))
        .await;
    let generation = peers.current_network_generation_sync();
    assert!(
        peers
            .is_data_path_admitted_for_generation(PEER, generation, true)
            .await
    );
    assert!(peers.connections.read().await[PEER].has_current_authoritative_direct(generation));
    (peers, generation)
}

#[tokio::test]
async fn settled_direct_scheduling_shares_reader_without_taking_epoch() {
    let (peers, generation) = settled_direct_fixture().await;
    let gate = peers.network_epoch_gate();
    let epoch = gate.lock().await;
    let reader = peers.connections.read().await;
    let before = format!("{:?}", reader[PEER]);
    let future = peers.is_data_path_admitted_for_generation(PEER, generation, true);
    tokio::pin!(future);
    assert_eq!(futures_util::poll!(future.as_mut()), Poll::Ready(true));
    assert_eq!(format!("{:?}", reader[PEER]), before);
    drop(reader);
    drop(epoch);
}

#[tokio::test]
async fn unsettled_or_stale_direct_scheduling_keeps_original_writer_fallback() {
    for variant in 0..5 {
        let (peers, generation) = settled_direct_fixture().await;
        let expected = if variant == 4 {
            generation + 1
        } else {
            generation
        };
        {
            let mut connections = peers.connections.write().await;
            let conn = connections.get_mut(PEER).unwrap();
            match variant {
                0 => conn.online = false,
                1 => conn.state = ConnectionState::Closed,
                2 => conn.direct_generation = generation + 1,
                3 => conn.relay_first.gate_generation = None,
                _ => {}
            }
        }
        let gate = peers.network_epoch_gate();
        let epoch = gate.lock().await;
        let future = peers.is_data_path_admitted_for_generation(PEER, expected, true);
        tokio::pin!(future);
        assert!(
            futures_util::poll!(future.as_mut()).is_pending(),
            "variant={variant}"
        );
        drop(epoch);
        let admitted = future.await;
        assert_eq!(admitted, variant == 3, "variant={variant}");
    }
}

#[tokio::test]
async fn settled_direct_scheduling_respects_writer_and_generation_change() {
    let (peers, generation) = settled_direct_fixture().await;
    let writer = peers.connections.write().await;
    let future = peers.is_data_path_admitted_for_generation(PEER, generation, true);
    tokio::pin!(future);
    assert!(futures_util::poll!(future.as_mut()).is_pending());
    assert!(peers.network_epoch_gate().try_lock().is_ok());
    drop(writer);
    assert!(future.await);
    assert_ne!(
        peers
            .advance_network_generation("direct scheduling snapshot expired")
            .await,
        generation
    );
    assert!(
        !peers
            .is_data_path_admitted_for_generation(PEER, generation, true)
            .await
    );
}
