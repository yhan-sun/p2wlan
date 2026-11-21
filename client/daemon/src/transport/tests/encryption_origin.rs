// S3A tests actual successful-encryption metadata only. No network-G source,
// physical send, final owner guard or business ACK is asserted here.

fn s3a_outbound(sequence: u16) -> OutboundPacket {
    OutboundPacket {
        room_authorization: None,
        trace: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x530a,
            sequence,
            b"actual-successful-encryption-origin",
        ),
    }
}

fn s3a_source(encrypted: &EncryptedOutboundWithSource) -> &OriginalEncryptionSource {
    encrypted
        .source()
        .expect("actual sourced encryption succeeded")
}

async fn s3a_fast_success(
    transport: &WireGuardTransport,
    peers: &PeerManager,
    packet: OutboundPacket,
    expected_instance: u64,
) -> EncryptedOutboundWithSource {
    let original = packet.clone();
    let emit = transport.acquire_outbound_emit_guard("peer-a").await;
    let epoch_gate = peers.network_epoch_gate();
    let epoch = epoch_gate.lock().await;
    let result = transport
        .try_encrypt_outbound_with_emit_guard_for_session_and_source(packet, expected_instance);
    drop(epoch);
    drop(emit);
    match result {
        SessionBoundEncryptionWithSource::Encrypted {
            packet, plaintext, ..
        } => {
            assert_eq!(
                plaintext, original,
                "the original fallback plaintext survives"
            );
            packet
        }
        _ => panic!("the actual authorized active slot must encrypt"),
    }
}

#[tokio::test]
async fn s3a_slow_source_keeps_original_life_after_delayed_readd() {
    let (peers, info, original_life) = s1_peer_scope_owner().await;
    let (mut remote, local) = establish_sessions();
    let (transport, _raw_rx) = WireGuardTransport::new();
    s1_install_authorized(&transport, None, local, original_life).await;
    let instance = transport
        .session_status("peer-a")
        .await
        .active_session_instance
        .unwrap();
    let original = s3a_outbound(1);
    let before = Instant::now();
    let encrypted = transport
        .encrypt_outbound_with_source(original.clone())
        .await
        .unwrap()
        .unwrap();
    let after = Instant::now();
    let (ciphertext, source) = encrypted.into_parts();
    let source: OriginalEncryptionSource = source.expect("actual sourced encryption succeeded");

    let replacement_life = s1_readd_peer(&peers, &info).await;
    assert_ne!(original_life, replacement_life);
    assert_eq!(
        remote.decrypt_from_bytes(&ciphertext.wire_bytes).unwrap(),
        original.packet
    );
    assert_eq!(wire_counter(&ciphertext.wire_bytes), Some(0));
    assert_eq!(source.peer_id(), "peer-a");
    assert_eq!(source.session_instance(), instance);
    assert_eq!(source.authorized_peer_lifecycle(), Some(original_life));
    assert_ne!(source.authorized_peer_lifecycle(), Some(replacement_life));
    assert!(before <= source.encrypted_at() && source.encrypted_at() <= after);
    assert!(source.belongs_to(&transport.clone()));
    let (foreign, _foreign_rx) = WireGuardTransport::new();
    assert!(!source.belongs_to(&foreign));

    // A later current membership observation cannot authenticate the old key.
    let next = s3a_outbound(2);
    let later = transport
        .encrypt_outbound_with_source(next.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        s3a_source(&later).authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_eq!(
        remote
            .decrypt_from_bytes(&later.packet().wire_bytes)
            .unwrap(),
        next.packet
    );
}

#[tokio::test]
async fn s3a_fast_source_keeps_actual_slot_after_delayed_epoch_and_readd() {
    let (peers, info, original_life) = s1_peer_scope_owner().await;
    let (mut remote, local) = establish_sessions();
    let (transport, _raw_rx) = WireGuardTransport::new();
    s1_install_authorized(&transport, None, local, original_life).await;
    let instance = transport
        .session_status("peer-a")
        .await
        .active_session_instance
        .unwrap();
    let original = s3a_outbound(3);
    let before = Instant::now();
    let encrypted = s3a_fast_success(&transport, &peers, original.clone(), instance).await;
    let after = Instant::now();

    let prior_g = peers.current_network_generation_sync();
    let current_g = peers
        .advance_network_generation("s3a source is not envelope G")
        .await;
    assert_ne!(prior_g, current_g);
    let replacement_life = s1_readd_peer(&peers, &info).await;
    assert_eq!(
        remote
            .decrypt_from_bytes(&encrypted.packet().wire_bytes)
            .unwrap(),
        original.packet
    );
    assert!(encrypted.packet().is_business);
    assert_eq!(wire_counter(&encrypted.packet().wire_bytes), Some(0));
    assert_eq!(s3a_source(&encrypted).session_instance(), instance);
    assert_eq!(
        s3a_source(&encrypted).authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_ne!(
        s3a_source(&encrypted).authorized_peer_lifecycle(),
        Some(replacement_life)
    );
    assert!(
        before <= s3a_source(&encrypted).encrypted_at()
            && s3a_source(&encrypted).encrypted_at() <= after
    );
    assert!(s3a_source(&encrypted).belongs_to(&transport));

    // Same installed old key still supplies its original L, regardless of G.
    let next = s3a_outbound(4);
    let later = s3a_fast_success(&transport, &peers, next.clone(), instance).await;
    assert_eq!(
        s3a_source(&later).authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_eq!(
        remote
            .decrypt_from_bytes(&later.packet().wire_bytes)
            .unwrap(),
        next.packet
    );
}

#[tokio::test]
async fn s3a_rekey_cannot_upgrade_old_slow_or_fast_source() {
    let (peers, info, original_life) = s1_peer_scope_owner().await;
    let (mut old_remote, old_local) = establish_sessions();
    let (transport, _raw_rx) = WireGuardTransport::new();
    s1_install_authorized(&transport, None, old_local, original_life).await;
    let old_instance = transport
        .session_status("peer-a")
        .await
        .active_session_instance
        .unwrap();
    let slow_plain = s3a_outbound(5);
    let old_slow = transport
        .encrypt_outbound_with_source(slow_plain.clone())
        .await
        .unwrap()
        .unwrap();
    let fast_plain = s3a_outbound(6);
    let old_fast = s3a_fast_success(&transport, &peers, fast_plain.clone(), old_instance).await;
    let slow_at = s3a_source(&old_slow).encrypted_at();
    let fast_at = s3a_source(&old_fast).encrypted_at();

    let current_life = s1_readd_peer(&peers, &info).await;
    let (mut new_remote, new_local) = establish_sessions();
    s1_install_authorized(&transport, None, new_local, current_life).await;
    let new_instance = transport
        .session_status("peer-a")
        .await
        .active_session_instance
        .unwrap();
    assert_ne!(old_instance, new_instance);
    // Consume old ciphertext only now: it remains output of the original real key.
    assert_eq!(
        old_remote
            .decrypt_from_bytes(&old_slow.packet().wire_bytes)
            .unwrap(),
        slow_plain.packet
    );
    assert_eq!(
        old_remote
            .decrypt_from_bytes(&old_fast.packet().wire_bytes)
            .unwrap(),
        fast_plain.packet
    );
    for old in [&old_slow, &old_fast] {
        assert_eq!(s3a_source(old).session_instance(), old_instance);
        assert_eq!(
            s3a_source(old).authorized_peer_lifecycle(),
            Some(original_life)
        );
        assert_ne!(
            s3a_source(old).authorized_peer_lifecycle(),
            Some(current_life)
        );
    }
    assert_eq!(s3a_source(&old_slow).encrypted_at(), slow_at);
    assert_eq!(s3a_source(&old_fast).encrypted_at(), fast_at);

    let new_slow_plain = s3a_outbound(7);
    let new_slow = transport
        .encrypt_outbound_with_source(new_slow_plain.clone())
        .await
        .unwrap()
        .unwrap();
    let new_fast_plain = s3a_outbound(8);
    let new_fast = s3a_fast_success(&transport, &peers, new_fast_plain.clone(), new_instance).await;
    assert_eq!(
        new_remote
            .decrypt_from_bytes(&new_slow.packet().wire_bytes)
            .unwrap(),
        new_slow_plain.packet
    );
    assert_eq!(
        new_remote
            .decrypt_from_bytes(&new_fast.packet().wire_bytes)
            .unwrap(),
        new_fast_plain.packet
    );
    for new in [&new_slow, &new_fast] {
        assert_eq!(s3a_source(new).session_instance(), new_instance);
        assert_eq!(
            s3a_source(new).authorized_peer_lifecycle(),
            Some(current_life)
        );
    }
}

#[tokio::test]
async fn s3a_wrong_expected_fast_preserves_plaintext_and_allocates_no_counter() {
    let (peers, _info, life) = s1_peer_scope_owner().await;
    let (mut remote, local) = establish_sessions();
    let (transport, _raw_rx) = WireGuardTransport::new();
    s1_install_authorized(&transport, None, local, life).await;
    let actual_instance = transport
        .session_status("peer-a")
        .await
        .active_session_instance
        .unwrap();
    let wrong_instance = actual_instance.checked_add(1).unwrap();
    let original = s3a_outbound(9);
    let emit = transport.acquire_outbound_emit_guard("peer-a").await;
    let epoch_gate = peers.network_epoch_gate();
    let epoch = epoch_gate.lock().await;
    let rejected = transport.try_encrypt_outbound_with_emit_guard_for_session_and_source(
        original.clone(),
        wrong_instance,
    );
    drop(epoch);
    drop(emit);
    match rejected {
        SessionBoundEncryptionWithSource::Unavailable {
            packet,
            reason: SessionUnavailableReason::SessionInstanceMismatch,
        } => assert_eq!(packet, original),
        _ => panic!("wrong cached expectation must return original plaintext without a source"),
    }
    let first = s3a_fast_success(&transport, &peers, original.clone(), actual_instance).await;
    // This cryptographic oracle proves the wrong expectation did not encrypt.
    assert_eq!(wire_counter(&first.packet().wire_bytes), Some(0));
    assert_eq!(
        remote
            .decrypt_from_bytes(&first.packet().wire_bytes)
            .unwrap(),
        original.packet
    );
    assert_eq!(s3a_source(&first).session_instance(), actual_instance);
}

#[tokio::test]
async fn s3a_legacy_life_stays_unknown_in_slow_fast_and_public_api() {
    let (peers, _info, current_life) = s1_peer_scope_owner().await;
    let (mut remote, local) = establish_sessions();
    let (transport, _raw_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local).await;
    let instance = transport
        .session_status("peer-a")
        .await
        .active_session_instance
        .unwrap();
    let slow_plain = s3a_outbound(10);
    let slow = transport
        .encrypt_outbound_with_source(slow_plain.clone())
        .await
        .unwrap()
        .unwrap();
    let fast_plain = s3a_outbound(11);
    let fast = s3a_fast_success(&transport, &peers, fast_plain.clone(), instance).await;
    assert!(peers.peer_session_is_current_sync("peer-a", current_life));
    for unknown in [&slow, &fast] {
        assert_eq!(s3a_source(unknown).authorized_peer_lifecycle(), None);
        assert_eq!(s3a_source(unknown).session_instance(), instance);
        assert!(s3a_source(unknown).belongs_to(&transport));
    }
    assert_eq!(
        remote
            .decrypt_from_bytes(&slow.packet().wire_bytes)
            .unwrap(),
        slow_plain.packet
    );
    assert_eq!(
        remote
            .decrypt_from_bytes(&fast.packet().wire_bytes)
            .unwrap(),
        fast_plain.packet
    );

    // Existing callers still receive the unchanged public ciphertext type.
    let public_plain = s3a_outbound(12);
    let public: EncryptedPeerPacket = transport
        .encrypt_outbound(public_plain.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        remote.decrypt_from_bytes(&public.wire_bytes).unwrap(),
        public_plain.packet
    );
}
