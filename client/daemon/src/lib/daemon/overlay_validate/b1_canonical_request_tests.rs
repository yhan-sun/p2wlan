use super::*;
use crate::overlay_requests::{CanonicalOverlayRequest, RequestSendToken};

// B13 exercises actual minters + original MockTun inject/read, without a
// DataPlane consumer, WireGuard crypto, physical send or native ACK claim.
async fn read_token_request(
    tun: &mut p2pnet_tun::mock::MockTunDevice,
) -> (u64, u32, RequestSendToken) {
    let (nonce, seq) = Fixture::read_requests(tun, 1).await[0];
    let context = tun
        .take_last_read_context()
        .expect("real tracked injection carries context");
    let token = RequestSendToken::from_read_context(context)
        .expect("only actual canonical minter creates the sealed context type");
    (nonce, seq, token)
}

#[tokio::test]
async fn canonical_periodic_real_read_has_exact_accepted_identity() {
    let mut fixture = Fixture::new().await;
    let expected_life = fixture.peers.peer_session_generation_sync(PEER).unwrap();
    assert_eq!(fixture.inject_periodic().await, 1);
    let (nonce, seq, token) = tokio::time::timeout(
        Duration::from_secs(1),
        read_token_request(fixture.tun.as_mut().unwrap()),
    )
    .await
    .expect("original real read remains bounded");
    let record = token
        .request()
        .expect("original retained success stays live");
    assert!(Arc::ptr_eq(&record, &fixture.sent_nonces[&nonce]));
    assert_eq!(record.nonce, nonce);
    assert_eq!(record.seq, seq);
    assert_eq!(record.peer_id, PEER);
    assert_eq!(
        record.generation,
        fixture.peers.current_network_generation_sync()
    );
    assert_eq!(record.expected_target_lifecycle(), Some(expected_life));
    assert!(record.belongs_to(&fixture.peers));
    assert!(record.injection_accepted());
    assert_eq!(record.local_vip(), LOCAL_VIP);
    assert_eq!(record.target_vip(), PEER_VIP);
    assert!(record.sent_at.elapsed() <= OVERLAY_NONCE_TTL);
    assert!(fixture
        .tun
        .as_mut()
        .unwrap()
        .take_last_read_context()
        .is_none());
    assert!(RequestSendToken::from_read_context(Box::new(String::from("foreign"))).is_none());
    let other = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    assert!(!record.belongs_to(&other));
    // No extra strong token ownership can resurrect a retired request.
    drop(record);
    fixture.sent_nonces.clear();
    assert!(token.request().is_none());
}

#[tokio::test]
async fn canonical_burst_shares_one_record_beyond_periodic_eviction() {
    let mut fixture = Fixture::new().await;
    fixture.arm_burst();
    let mut tun = fixture.tun.take().unwrap();
    let count = OVERLAY_NONCE_CAP + 1;
    let (_, requests) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(fixture.inject_burst_attempts(count), async {
            let mut requests = Vec::new();
            for _ in 0..count {
                requests.push(read_token_request(&mut tun).await);
            }
            requests
        })
    })
    .await
    .expect("real original 256 queue is drained concurrently, never enlarged");
    fixture.tun = Some(tun);
    assert_eq!(fixture.sent_nonces.len(), OVERLAY_NONCE_CAP);
    assert_eq!(fixture.bursts[PEER].nonces.len(), count);
    assert!(!fixture.sent_nonces.contains_key(&requests[0].0));
    for (nonce, seq, token) in &requests {
        let record = token
            .request()
            .expect("real burst view retains original identity");
        let burst_record = fixture.bursts[PEER]
            .nonces
            .iter()
            .find(|request| request.nonce == *nonce)
            .unwrap();
        assert!(Arc::ptr_eq(&record, burst_record));
        assert_eq!(record.seq, *seq);
        assert!(record.injection_accepted());
        if let Some(periodic) = fixture.sent_nonces.get(nonce) {
            assert!(Arc::ptr_eq(&record, periodic));
        }
    }
    let first_token = requests[0].2.clone();
    fixture.bursts.remove(PEER);
    assert!(first_token.request().is_none());
    let last_token = requests.last().unwrap().2.clone();
    assert!(last_token.request().is_some());
    fixture.sent_nonces.clear();
    assert!(last_token.request().is_none());
}

async fn replace_real_member(peers: &Arc<PeerManager>) -> crate::peer::PeerSessionGeneration {
    peers.remove_peer(PEER).await;
    peers
        .add_peer(&crate::control::PeerInfo {
            node_id: PEER.to_string(),
            public_key: "pk".to_string(),
            endpoint: "127.0.0.1:45003".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: PEER_VIP.to_string(),
            online: true,
            ..crate::control::PeerInfo::default()
        })
        .await;
    let generation = peers.current_network_generation_sync();
    peers
        .mark_relay_transport_ready(PEER, RELAY, generation)
        .await;
    assert!(peers.confirm_relay_peer(PEER, RELAY, generation).await);
    peers.peer_session_generation_sync(PEER).unwrap()
}

#[tokio::test]
async fn canonical_real_inject_backpressure_cannot_rebind_a_request_to_b() {
    for burst in [false, true] {
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut fixture = Fixture::new().await;
            let peers = fixture.peers.clone();
            let generation = peers.current_network_generation_sync();
            let life_a = peers.peer_session_generation_sync(PEER).unwrap();
            let mut tun = fixture.tun.take().unwrap();
            // Fill the genuine original queue. These unrelated byte inputs do
            // not manufacture canonical contexts or claim routed business.
            for _ in 0..256 {
                fixture.controller.inject(vec![0xee]).await.unwrap();
            }
            let expected_nonce = fixture.next_nonce.wrapping_add(1);
            let mut injection = Box::pin(async {
                if burst {
                    fixture.arm_burst();
                    fixture.inject_burst_attempts(1).await;
                    fixture.bursts[PEER].sent
                } else {
                    fixture.inject_periodic().await
                }
            });
            // Actual minter snapshots A and reaches the real full-queue send
            // before ready cancellation; no sleep or fake owner is needed.
            tokio::select! {
                biased;
                count = &mut injection => panic!("full original queue admitted {count}"),
                () = std::future::ready(()) => {}
            }
            let life_b = replace_real_member(&peers).await;
            assert_ne!(life_a, life_b);
            assert_eq!(peers.current_network_generation_sync(), generation);
            let mut one = [0; 1];
            assert_eq!(tun.read(&mut one).await.unwrap(), 1);
            assert_eq!(one, [0xee]);
            assert_eq!(injection.await, 1);
            for _ in 0..255 {
                assert_eq!(tun.read(&mut one).await.unwrap(), 1);
                assert_eq!(one, [0xee]);
            }
            let (nonce, seq, token) = read_token_request(&mut tun).await;
            assert_eq!(nonce, expected_nonce);
            let original = token.request().unwrap();
            assert!(Arc::ptr_eq(&original, &fixture.sent_nonces[&nonce]));
            assert_eq!(original.seq, seq);
            assert!(original.injection_accepted());
            assert_eq!(original.expected_target_lifecycle(), Some(life_a));
            assert!(original.belongs_to(&peers));
            assert!(!peers.peer_session_is_current_sync(PEER, life_a));
            assert!(peers.peer_session_is_current_sync(PEER, life_b));
            if burst {
                assert!(Arc::ptr_eq(&original, &fixture.bursts[PEER].nonces[0]));
            }
            fixture.tun = Some(tun);
            // A genuinely fresh target snapshot belongs to B. The old object
            // remains A; this tests expectation preservation, not final credit.
            assert_eq!(fixture.inject_periodic().await, 1);
            let (_, _, fresh_token) = read_token_request(fixture.tun.as_mut().unwrap()).await;
            let fresh = fresh_token.request().unwrap();
            assert_eq!(fresh.expected_target_lifecycle(), Some(life_b));
            assert_eq!(original.expected_target_lifecycle(), Some(life_a));
            assert!(!Arc::ptr_eq(&original, &fresh));
        })
        .await
        .expect("unchanged 1s local fixture window covers real owner/inject/read");
    }
}

#[tokio::test]
async fn canonical_real_inject_err_preserves_success_identity_and_fifo() {
    let mut fixture = Fixture::new().await;
    tokio::time::timeout(Duration::from_secs(1), async {
        for _ in 0..OVERLAY_NONCE_CAP {
            assert_eq!(fixture.inject_periodic().await, 1);
            fixture.take_one_request().await;
        }
    })
    .await
    .expect("real successful original registry fills within fixture window");
    let first_nonce = fixture.nonce_order[0];
    let first = fixture.sent_nonces[&first_nonce].clone();
    let first_seq = first.seq;
    let fifo = fixture.nonce_order.clone();
    let old_records: Vec<Arc<CanonicalOverlayRequest>> = fixture
        .nonce_order
        .iter()
        .map(|nonce| fixture.sent_nonces[nonce].clone())
        .collect();
    drop(fixture.tun.take());
    assert!(fixture.controller.inject(vec![0x45]).await.is_err());
    let failed_periodic = fixture.next_nonce.wrapping_add(1);
    assert_eq!(fixture.inject_periodic().await, 0);
    fixture.arm_burst();
    let failed_burst = fixture.next_nonce.wrapping_add(1);
    fixture.inject_burst_attempts(1).await;
    assert_eq!(fixture.bursts[PEER].sent, 0);
    assert!(fixture.bursts[PEER].nonces.is_empty());
    assert_eq!(fixture.sent_nonces.len(), OVERLAY_NONCE_CAP);
    assert_eq!(fixture.nonce_order, fifo);
    assert!(!fixture.sent_nonces.contains_key(&failed_periodic));
    assert!(!fixture.sent_nonces.contains_key(&failed_burst));
    for record in &old_records {
        assert!(Arc::ptr_eq(record, &fixture.sent_nonces[&record.nonce]));
        assert!(record.injection_accepted());
    }
    // Preserve the existing explicit post-decrypt diagnostic behavior. This
    // fabricated ingress Event is Unknown and is not a native ACK proof.
    fixture.echo(first_nonce, first_seq).await;
    assert_eq!(
        fixture.event_count("first_usable_bidirectional_overlay_ms"),
        1
    );
    assert_eq!(fixture.stats.received_valid, 1);
}
