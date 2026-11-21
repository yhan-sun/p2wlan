// C07/C08/C09/C11/C12: actual original request input plus real Noise crypto.
// No physical completion, native TUN, final ACK eligibility or once credit.
use crate::request_carriage::test_support::{mint_routed_request, peer_info, PEER};
use crate::request_carriage::{
    RawRequestDelivery, RequestEncryptionAttempt, RequestInputEligibility,
};

async fn authorized(
    transport: &WireGuardTransport,
    session: TransportSession,
    life: PeerSessionGeneration,
) {
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    transport
        .install_active_session_for_lifecycle_locked(PEER, None, session, life)
        .await;
    drop(emit);
}

async fn encrypt_fast(
    transport: &WireGuardTransport,
    peers: &PeerManager,
    delivery: RawRequestDelivery,
    instance: u64,
) -> (
    crate::request_carriage::EncryptedRequestDelivery,
    RawRequestDelivery,
) {
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let gate = peers.network_epoch_gate();
    let epoch = gate.lock().await;
    let result = transport.try_encrypt_request_with_emit_guard_for_session(delivery, instance);
    drop(epoch);
    drop(emit);
    match result {
        RequestEncryptionAttempt::Encrypted {
            packet, plaintext, ..
        } => (packet, plaintext),
        _ => panic!("actual ready expected slot must encrypt"),
    }
}

#[tokio::test]
async fn carriage_fast_actual_new_life_source_does_not_relabel_original_expectation() {
    let f = mint_routed_request().await;
    let original_life = f.record.expected_target_lifecycle().unwrap();
    let original_generation = f.record.generation;
    let original_created_at = f.record.sent_at;
    f.peers.remove_peer(PEER).await;
    f.peers.add_peer(&peer_info()).await;
    let actual_life = f.peers.peer_session_generation_sync(PEER).unwrap();
    assert_ne!(actual_life, original_life);
    let (session, mut remote) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    authorized(&transport, session, actual_life).await;
    let instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let before = Instant::now();
    let (ciphertext, plaintext) =
        encrypt_fast(&transport, &f.peers, f.delivery.clone(), instance).await;
    let after = Instant::now();
    let b = ciphertext.source().unwrap();
    assert_eq!(
        remote.decrypt_from_bytes(&ciphertext.wire_bytes).unwrap(),
        f.record.original_packet()
    );
    assert_eq!(b.peer_id(), PEER);
    assert_eq!(b.session_instance(), instance);
    assert_eq!(b.authorized_peer_lifecycle(), Some(actual_life));
    assert!(b.encrypted_at() >= before && b.encrypted_at() <= after);
    assert!(b.belongs_to(&transport));
    let (foreign, _foreign_rx) = WireGuardTransport::new();
    assert!(!b.belongs_to(&foreign));
    assert!(Arc::ptr_eq(
        &ciphertext.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    assert!(Arc::ptr_eq(
        &plaintext.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    assert_eq!(f.record.expected_target_lifecycle(), Some(original_life));
    assert_eq!(f.record.generation, original_generation);
    assert_eq!(f.record.sent_at, original_created_at);
}

#[tokio::test]
async fn carriage_slow_actual_source_and_legacy_key_unknown_are_separate_from_a() {
    let f = mint_routed_request().await;
    let life = f.record.expected_target_lifecycle().unwrap();
    let (session, mut remote) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    authorized(&transport, session, life).await;
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let before = Instant::now();
    let ciphertext = transport
        .encrypt_request_with_emit_guard(f.delivery.clone())
        .await
        .unwrap()
        .unwrap();
    let after = Instant::now();
    drop(emit);
    let b = ciphertext.source().unwrap();
    assert_eq!(
        remote.decrypt_from_bytes(&ciphertext.wire_bytes).unwrap(),
        f.record.original_packet()
    );
    assert_eq!(b.authorized_peer_lifecycle(), Some(life));
    assert!(b.belongs_to(&transport));
    assert!(b.encrypted_at() >= before && b.encrypted_at() <= after);
    assert!(Arc::ptr_eq(
        &ciphertext.binding().unwrap().token().request().unwrap(),
        &f.record
    ));

    let (session, mut legacy_remote) = establish_sessions();
    let (legacy_keys, _rx) = WireGuardTransport::new_with_request_carriage();
    assert!(!legacy_keys.add_session(PEER, session).await);
    let emit = legacy_keys.acquire_outbound_emit_guard(PEER).await;
    let unknown = legacy_keys
        .encrypt_request_with_emit_guard(f.delivery.clone())
        .await
        .unwrap()
        .unwrap();
    drop(emit);
    assert_eq!(
        legacy_remote
            .decrypt_from_bytes(&unknown.wire_bytes)
            .unwrap(),
        f.record.original_packet()
    );
    assert_eq!(unknown.source().unwrap().authorized_peer_lifecycle(), None);
    assert_eq!(f.record.expected_target_lifecycle(), Some(life));
    let legacy_instance = legacy_keys
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let (fast_unknown, _retry) =
        encrypt_fast(&legacy_keys, &f.peers, f.delivery.clone(), legacy_instance).await;
    assert_eq!(
        legacy_remote
            .decrypt_from_bytes(&fast_unknown.wire_bytes)
            .unwrap(),
        f.record.original_packet()
    );
    assert_eq!(
        fast_unknown.source().unwrap().authorized_peer_lifecycle(),
        None
    );
    assert_eq!(f.record.expected_target_lifecycle(), Some(life));

    let (absent, _rx) = WireGuardTransport::new_with_request_carriage();
    let emit = absent.acquire_outbound_emit_guard(PEER).await;
    assert!(absent
        .encrypt_request_with_emit_guard(f.delivery.clone())
        .await
        .unwrap()
        .is_none());
    drop(emit);
    assert!(Arc::ptr_eq(
        &f.delivery.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
}

#[tokio::test]
async fn carriage_fast_contention_and_stale_instance_return_same_plaintext_weak() {
    let f = mint_routed_request().await;
    let life = f.record.expected_target_lifecycle().unwrap();
    let (session, mut remote) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    authorized(&transport, session, life).await;
    let instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let gate = f.peers.network_epoch_gate();
    let epoch = gate.lock().await;
    let held_registry = transport.hold_session_registry_for_test().await;
    let contended =
        transport.try_encrypt_request_with_emit_guard_for_session(f.delivery.clone(), instance);
    drop(held_registry);
    let RequestEncryptionAttempt::Contended(raw) = contended else {
        panic!("actual locked registry must contend")
    };
    assert!(Arc::ptr_eq(
        &raw.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    assert_eq!(raw.packet, f.record.original_packet());
    let stale = transport.try_encrypt_request_with_emit_guard_for_session(raw, instance + 1);
    let RequestEncryptionAttempt::Unavailable {
        packet: raw,
        reason,
    } = stale
    else {
        panic!("wrong actual slot identity must miss")
    };
    assert_eq!(reason, SessionUnavailableReason::SessionInstanceMismatch);
    assert!(Arc::ptr_eq(
        &raw.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    drop(epoch);
    drop(emit);
    let (ciphertext, _plaintext) = encrypt_fast(&transport, &f.peers, raw, instance).await;
    assert_eq!(wire_counter(&ciphertext.wire_bytes), Some(0));
    assert_eq!(
        remote.decrypt_from_bytes(&ciphertext.wire_bytes).unwrap(),
        f.record.original_packet()
    );
}

#[tokio::test]
async fn carriage_retry_discards_old_ciphertext_and_uses_fresh_actual_b_same_a() {
    let f = mint_routed_request().await;
    let life = f.record.expected_target_lifecycle().unwrap();
    let (session, mut old_remote) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    authorized(&transport, session, life).await;
    let old_instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let (old_ciphertext, retry) =
        encrypt_fast(&transport, &f.peers, f.delivery.clone(), old_instance).await;
    assert_eq!(
        old_remote
            .decrypt_from_bytes(&old_ciphertext.wire_bytes)
            .unwrap(),
        f.record.original_packet()
    );
    assert_eq!(
        old_ciphertext.source().unwrap().session_instance(),
        old_instance
    );
    // This actual prior ciphertext/B owner ends before any re-encryption.
    drop(old_ciphertext);
    let (new_session, mut new_remote) = establish_sessions();
    let _old_slot = transport
        .replace_session_for_lifecycle(PEER, new_session, life)
        .await;
    let new_instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    assert_ne!(new_instance, old_instance);
    let (new_ciphertext, retry) = encrypt_fast(&transport, &f.peers, retry, new_instance).await;
    assert_eq!(
        new_remote
            .decrypt_from_bytes(&new_ciphertext.wire_bytes)
            .unwrap(),
        f.record.original_packet()
    );
    assert_eq!(wire_counter(&new_ciphertext.wire_bytes), Some(0));
    assert_eq!(
        new_ciphertext.source().unwrap().session_instance(),
        new_instance
    );
    assert_eq!(
        new_ciphertext.source().unwrap().authorized_peer_lifecycle(),
        Some(life)
    );
    assert!(Arc::ptr_eq(
        &retry.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    assert!(Arc::ptr_eq(
        &new_ciphertext.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
}

#[tokio::test]
async fn carriage_legacy_crypto_has_no_a_or_b_and_keeps_public_packet_literal() {
    let f = mint_routed_request().await;
    let (session, mut remote) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    assert!(!transport.add_session(PEER, session).await);
    let legacy = OutboundPacket {
        room_authorization: None,
        peer_id: PEER.to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: f.record.original_packet().to_vec(),
        trace: None,
    };
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let encrypted = transport
        .encrypt_request_with_emit_guard(legacy.clone().into())
        .await
        .unwrap()
        .unwrap();
    drop(emit);
    assert!(encrypted.binding().is_none());
    assert!(encrypted.source().is_none());
    assert_eq!(
        remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
        legacy.packet
    );
    let public: EncryptedPeerPacket = transport
        .encrypt_outbound(legacy.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        remote.decrypt_from_bytes(&public.wire_bytes).unwrap(),
        legacy.packet
    );
    let instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let (fast, retry) = encrypt_fast(&transport, &f.peers, legacy.clone().into(), instance).await;
    assert!(fast.binding().is_none());
    assert!(fast.source().is_none());
    assert!(retry.binding().is_none());
    assert_eq!(
        remote.decrypt_from_bytes(&fast.wire_bytes).unwrap(),
        legacy.packet
    );
}

#[tokio::test]
async fn carriage_original_full_packet_is_one_shared_commitment_and_weak_has_no_keeper() {
    let f = mint_routed_request().await;
    assert_eq!(f.record.original_packet().len(), 179);
    assert_eq!(f.delivery.packet, f.record.original_packet());
    assert_ne!(
        f.delivery.packet.as_ptr(),
        f.record.original_packet().as_ptr()
    );
    let copy = f.delivery.clone();
    assert_eq!(Arc::strong_count(&f.record), 1);
    assert!(std::mem::size_of::<RawRequestDelivery>() > std::mem::size_of::<OutboundPacket>());
    assert!(Arc::ptr_eq(
        &copy.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    assert_eq!(
        copy.binding().unwrap().eligibility_at(Instant::now()),
        RequestInputEligibility::AcceptedInput
    );
    let original_sent_at = f.record.sent_at;
    assert_eq!(
        copy.binding().unwrap().token().request().unwrap().sent_at,
        original_sent_at
    );
    drop(f.controller); // Retiring the original input controller cannot keep a canonical alive.
    drop(f.record);
    assert_eq!(
        copy.binding().unwrap().eligibility_at(Instant::now()),
        RequestInputEligibility::Retired
    );
    assert!(copy.binding().unwrap().token().request().is_none());
}
