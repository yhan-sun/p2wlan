// C09/C10: real original slow driver, clone/admission and bounded arguments.
use super::super::test_support::establish_sessions;
use super::*;
use crate::dataplane::DataPlane;
use crate::request_carriage::test_probe::{HandoffArgumentPoint, RequestHandoffArgumentProbe};
use crate::request_carriage::test_support::{
    mint_input_request, mint_routed_request, InputRequestFixture, PEER,
};
use crate::request_carriage::RequestInputEligibility;
use crate::transport::wire_counter;

#[tokio::test]
async fn carriage_slow_driver_retry_keeps_a_and_discards_allocated_ciphertext_b() {
    let f = mint_routed_request().await;
    let life = f.record.expected_target_lifecycle().unwrap();
    let (session, mut remote) = establish_sessions();
    let (transport, _raw_rx) = WireGuardTransport::new_with_request_carriage();
    let transport =
        transport.with_request_handoff_probe(Arc::new(RequestHandoffArgumentProbe::new()));
    let _ = transport
        .replace_session_for_lifecycle(PEER, session, life)
        .await;
    let udp = RwLock::new(None);
    let relay = RwLock::new(None);
    let outcome = encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        false,
        &udp,
        &relay,
        true,
        Some(Instant::now() + Duration::from_secs(1)),
        None,
    )
    .await;
    let EncryptSendOutcome::Retryable { packet: retry, .. } = outcome else {
        panic!("no published writer must return original plaintext for retry")
    };
    assert_eq!(retry.packet, f.record.original_packet());
    assert!(Arc::ptr_eq(
        &retry.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    // No receiver or successful physical writer exists in this negative control.
    // The subsequent real encryption allocates the next counter, never replays
    // the old ciphertext that was dropped together with its lexical B owner.
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let fresh = transport
        .encrypt_request_with_emit_guard(retry)
        .await
        .unwrap()
        .unwrap();
    drop(emit);
    assert_eq!(wire_counter(&fresh.wire_bytes), Some(1));
    assert_eq!(
        remote.decrypt_from_bytes(&fresh.wire_bytes).unwrap(),
        f.record.original_packet()
    );
    assert!(Arc::ptr_eq(
        &fresh.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
}

#[tokio::test]
async fn carriage_slow_preparation_cancel_and_expired_deadline_preserve_identity_without_counter() {
    let f = mint_routed_request().await;
    let life = f.record.expected_target_lifecycle().unwrap();
    let (session, mut remote) = establish_sessions();
    let (transport, _raw_rx) = WireGuardTransport::new_with_request_carriage();
    let _ = transport
        .replace_session_for_lifecycle(PEER, session, life)
        .await;
    let udp = RwLock::new(None);
    let relay = RwLock::new(None);
    let held = transport.acquire_outbound_emit_guard(PEER).await;
    let mut pending = Box::pin(encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        false,
        &udp,
        &relay,
        true,
        Some(Instant::now() + Duration::from_secs(1)),
        None,
    ));
    assert!(matches!(
        futures_util::poll!(pending.as_mut()),
        std::task::Poll::Pending
    ));
    assert_eq!(Arc::strong_count(&f.record), 1);
    drop(pending);
    drop(held);
    let expired = encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        false,
        &udp,
        &relay,
        true,
        Some(Instant::now()),
        None,
    )
    .await;
    let EncryptSendOutcome::Terminal {
        packet,
        reason_code,
        ..
    } = expired
    else {
        panic!("expired original deadline must terminate")
    };
    assert_eq!(reason_code, REASON_OUTBOUND_DELIVERY_DEADLINE);
    assert!(Arc::ptr_eq(
        &packet.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    assert_eq!(
        packet.binding().unwrap().eligibility_at(Instant::now()),
        RequestInputEligibility::AcceptedInput
    );
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let fresh = transport
        .encrypt_request_with_emit_guard(packet)
        .await
        .unwrap()
        .unwrap();
    drop(emit);
    assert_eq!(wire_counter(&fresh.wire_bytes), Some(0));
    assert_eq!(
        remote.decrypt_from_bytes(&fresh.wire_bytes).unwrap(),
        f.record.original_packet()
    );
}

#[tokio::test]
async fn carriage_original_full_chain_reaches_slow_bounded_arguments_and_actual_local_udp() {
    let InputRequestFixture {
        peers,
        controller,
        tun,
        record,
    } = mint_input_request().await;
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    // Register the actual receiver through the existing candidate owner. A
    // non-host source keeps this control on the original slow selector path.
    peers
        .add_candidates_with_sources(
            PEER,
            &[endpoint.to_string()],
            &HashMap::from([(endpoint.to_string(), "srflx".to_string())]),
        )
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_endpoint = udp.local_addr().unwrap();
    peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            PEER,
            endpoint,
            Some(Duration::from_millis(1)),
            Some(local_endpoint),
        )
        .await;
    peers
        .record_direct_success_with_local_endpoint(PEER, Some(endpoint), Some(local_endpoint))
        .await;
    let selection = peers
        .select_path_for_data_with_local_endpoint(PEER, true, false, Some(local_endpoint))
        .await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert!(selection.direct_confirmed);
    assert!(peers
        .active_direct_path_snapshot(PEER, record.generation, true)
        .await
        .is_none());
    assert!(!udp.peer_requires_direct_business_budget(PEER));
    let (session, mut remote) = establish_sessions();
    let probe = Arc::new(RequestHandoffArgumentProbe::new());
    let (transport, raw_rx) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_request_handoff_probe(probe.clone());
    let life = record.expected_target_lifecycle().unwrap();
    let _ = transport
        .replace_session_for_lifecycle(PEER, session, life)
        .await;
    let instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let (mut dataplane, dp_rx) = DataPlane::new_with_request_carriage(tun, peers.clone());
    let forward_transport = transport.clone();
    let forward = tokio::spawn(async move {
        forward_transport
            .run_outbound_with_request_carriage(dp_rx)
            .await
    });
    let (relay_tx, relay_rx) = watch::channel(false);
    let (kick_tx, _kick_rx) = watch::channel(0u64);
    let worker = tokio::spawn(super::super::run_network_outbound_with_request_carriage(
        raw_rx.into(),
        transport.clone(),
        peers.clone(),
        true,
        Arc::new(RwLock::new(Some(udp))),
        Arc::new(RwLock::new(None)),
        relay_rx,
        RelayStartupWait {
            relay_expected: false,
            timeout: None,
        },
        kick_tx,
        ConnectionTimeline::new("carriage-slow-chain", 0),
    ));
    let before = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(1),
        dataplane.read_and_route_once(&mut [0u8; 512]),
    )
    .await
    .unwrap()
    .unwrap();
    drop(dataplane);
    tokio::time::timeout(Duration::from_secs(1), forward)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut wire = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    let after = Instant::now();
    assert_eq!(
        remote.decrypt_from_bytes(&wire[..n]).unwrap(),
        record.original_packet()
    );
    let observed = probe
        .recorded
        .lock()
        .unwrap()
        .take()
        .expect("real original bounded argument was observed");
    assert_eq!(observed.point, HandoffArgumentPoint::SlowBoundedEntry);
    assert!(Arc::ptr_eq(
        &observed.token.unwrap().request().unwrap(),
        &record
    ));
    let b = observed.source.unwrap();
    assert_eq!(b.peer_id, PEER);
    assert_eq!(b.session_instance, instance);
    assert_eq!(b.authorized_peer_lifecycle, Some(life));
    assert!(b.encrypted_at >= before && b.encrypted_at <= after);
    assert!(b.belongs_to_transport);
    // Closing the original lifecycle watch retires the actual actor; no extra
    // metadata observer task or queue is used for this chain.
    drop(relay_tx);
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    drop(controller);
}
