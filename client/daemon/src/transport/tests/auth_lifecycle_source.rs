// S1 exercises real Noise/WireGuard crypto with local, explicit authorization.
// These are transport metadata tests, not daemon authentication/final-ACK tests.
async fn s1_peer_scope_owner() -> (PeerManager, PeerInfo, PeerSessionGeneration) {
    let peers = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let info = PeerInfo {
        node_id: "peer-a".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        endpoint: "198.51.100.70:51820".to_string(),
        online: true,
        ..PeerInfo::default()
    };
    peers.add_peer(&info).await;
    let lifecycle = peers.peer_session_generation_sync("peer-a").unwrap();
    (peers, info, lifecycle)
}

async fn s1_readd_peer(peers: &PeerManager, info: &PeerInfo) -> PeerSessionGeneration {
    let old = peers.peer_session_generation_sync("peer-a").unwrap();
    peers.remove_peer("peer-a").await;
    peers.add_peer(info).await;
    let current = peers.peer_session_generation_sync("peer-a").unwrap();
    assert_ne!(
        old, current,
        "the real membership owner must change lifecycle"
    );
    assert!(!peers.peer_session_is_current_sync("peer-a", old));
    current
}

async fn s1_install_authorized(
    transport: &WireGuardTransport,
    token: Option<String>,
    session: TransportSession,
    lifecycle: PeerSessionGeneration,
) {
    let emit_lock = transport.outbound_emit_lock("peer-a").await;
    let guard = emit_lock.lock().await;
    transport
        .install_active_session_for_lifecycle_locked("peer-a", token, session, lifecycle)
        .await;
    drop(guard);
}

fn s1_packet(sequence: u16) -> Vec<u8> {
    Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        0x5301,
        sequence,
        b"actual-wg-slot-source",
    )
}

// Reuse the original fixture for all other cases. This variant additionally
// retains the actual responder's cached keys for exact-key restage, not a fake
// constructor or independently negotiated replacement.
fn s1_establish_cached_sessions() -> (
    TransportSession,
    TransportSession,
    p2pnet_wireguard::TransportKeyPair,
) {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut responder = HandshakeResponder::new(node_b, None);
    let init = initiator.create_initiation().unwrap();
    let (response, responder_keys) = responder.consume_initiation_and_respond(&init).unwrap();
    let initiator_keys = initiator.consume_response(&response).unwrap();
    (
        TransportSession::new(initiator_keys),
        TransportSession::new(responder_keys.clone()),
        responder_keys,
    )
}

#[tokio::test]
async fn s1_legacy_real_decrypt_is_unknown_and_public_api_stays_compatible() {
    let (mut remote, local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local).await;
    let packet = s1_packet(1);
    let wire = remote.encrypt_to_bytes(&packet).unwrap();
    let inbound = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inbound.packet.packet, packet);
    assert_eq!(inbound.source.peer_id(), "peer-a");
    assert_eq!(inbound.source.authorized_peer_lifecycle(), None);
    assert_eq!(
        inbound.packet.session_instance,
        Some(inbound.source.session_instance())
    );
    assert!(!inbound.source.is_previous_session());
    assert!(inbound.source.belongs_to(&transport.clone()));
    let (other_owner, _other_rx) = WireGuardTransport::new();
    assert!(!inbound.source.belongs_to(&other_owner));
    assert!(matches!(
        transport.decrypt_inbound_with_source(&wire).await,
        Err(InboundDecryptError::Decrypt(
            WireGuardError::ReplayDetected(0)
        ))
    ));
    let packet = s1_packet(2);
    let wire = remote.encrypt_to_bytes(&packet).unwrap();
    let legacy: InboundPacket = transport.decrypt_inbound(&wire).await.unwrap().unwrap();
    assert_eq!(legacy.packet, packet);
}

#[tokio::test]
async fn s1_active_key_retains_original_life_across_network_epoch_and_same_id_readd() {
    let (peers, info, original_life) = s1_peer_scope_owner().await;
    let (mut remote, local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    s1_install_authorized(&transport, None, local, original_life).await;
    let original_network = peers.current_network_generation_sync();
    let current_network = peers
        .advance_network_generation("s1 distinct envelope epoch")
        .await;
    assert_ne!(original_network, current_network);
    assert!(peers.peer_session_is_current_sync("peer-a", original_life));
    let packet = s1_packet(3);
    let wire = remote.encrypt_to_bytes(&packet).unwrap();
    let before_readd = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before_readd.packet.packet, packet);
    assert_eq!(
        before_readd.source.authorized_peer_lifecycle(),
        Some(original_life)
    );

    let replacement_life = s1_readd_peer(&peers, &info).await;
    let packet = s1_packet(4);
    let wire = remote.encrypt_to_bytes(&packet).unwrap();
    let after_readd = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_readd.packet.packet, packet);
    assert_eq!(
        after_readd.source.authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_ne!(
        after_readd.source.authorized_peer_lifecycle(),
        Some(replacement_life)
    );
    assert_eq!(
        before_readd.source.session_instance(),
        after_readd.source.session_instance()
    );
    // S1 deliberately still delivers crypto-valid old-life packets; S3 gates credit.
}

#[tokio::test]
async fn s1_pending_source_is_fixed_before_promotion_wait_and_survives_commit() {
    let (peers, info, original_life) = s1_peer_scope_owner().await;
    let (_old_remote, old_local) = establish_sessions();
    let (mut remote, local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    transport.add_session("peer-a", old_local).await;
    assert_eq!(
        transport
            .stage_responder_session_for_lifecycle(
                "peer-a",
                "s1-pending".to_string(),
                local,
                original_life,
            )
            .await,
        ResponderSessionStage::Staged { had_active: true },
    );
    assert_eq!(
        transport
            .commit_responder_session("peer-a", "s1-pending")
            .await,
        ResponderSessionCommit::PendingConfirmation,
    );
    let emit_lock = transport.outbound_emit_lock("peer-a").await;
    let emit_guard = emit_lock.lock().await;
    let packet = s1_packet(5);
    let wire = remote.encrypt_to_bytes(&packet).unwrap();
    let mut decrypt = Box::pin(transport.decrypt_inbound_with_source(&wire));
    assert!(futures_util::poll!(&mut decrypt).is_pending());
    assert!(
        transport.sessions.try_lock().is_ok(),
        "promotion must release sessions before emit wait"
    );
    // Consumed replay state proves the first future really decrypted, rather
    // than merely waiting at an earlier fixture or API boundary.
    assert!(matches!(
        transport.decrypt_inbound_with_source(&wire).await,
        Err(InboundDecryptError::Decrypt(
            WireGuardError::ReplayDetected(0)
        ))
    ));
    let after_crypto_before_release = Instant::now();
    let replacement_life = s1_readd_peer(&peers, &info).await;
    drop(emit_guard);
    let inbound = decrypt.await.unwrap().unwrap();
    assert_eq!(inbound.packet.packet, packet);
    assert!(inbound.source.authenticated_at() <= after_crypto_before_release);
    assert_eq!(
        inbound.source.authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_ne!(
        inbound.source.authorized_peer_lifecycle(),
        Some(replacement_life)
    );
    assert!(!inbound.source.is_previous_session());
    assert_eq!(
        transport
            .session_instance_state("peer-a", inbound.source.session_instance())
            .await,
        (true, true),
    );
    let packet = s1_packet(6);
    let wire = remote.encrypt_to_bytes(&packet).unwrap();
    let promoted = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(promoted.packet.packet, packet);
    assert_eq!(
        promoted.source.authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_eq!(
        promoted.source.session_instance(),
        inbound.source.session_instance()
    );
}

#[tokio::test]
async fn s1_bound_duplicate_cannot_reauthorize_legacy_or_old_life_key() {
    let (peers, info, old_life) = s1_peer_scope_owner().await;
    let current_life = s1_readd_peer(&peers, &info).await;
    let (mut original_remote, original_local) = establish_sessions();
    let (_replacement_remote, replacement_local) = establish_sessions();
    let (_same_scope_remote, same_scope_local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    transport
        .stage_responder_session_for_lifecycle(
            "peer-a",
            "same-scope".to_string(),
            original_local,
            old_life,
        )
        .await;
    assert_eq!(
        transport
            .restage_cached_responder_session_for_lifecycle(
                "peer-a",
                "same-scope".to_string(),
                replacement_local,
                current_life,
            )
            .await,
        ResponderSessionStage::StaleDuplicate,
    );
    assert_eq!(
        transport
            .stage_responder_session_for_lifecycle(
                "peer-a",
                "same-scope".to_string(),
                same_scope_local,
                old_life,
            )
            .await,
        ResponderSessionStage::ReplayableDuplicate { had_active: false },
    );
    let packet = s1_packet(7);
    let wire = original_remote.encrypt_to_bytes(&packet).unwrap();
    let original = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        original.packet.packet, packet,
        "duplicate must not install replacement keys"
    );
    assert_eq!(original.source.authorized_peer_lifecycle(), Some(old_life));

    let (_wrong_remote, wrong_local) = establish_sessions();
    assert_eq!(
        transport
            .stage_responder_session_for_lifecycle(
                "peer-a",
                "same-scope".to_string(),
                wrong_local,
                current_life,
            )
            .await,
        ResponderSessionStage::StaleDuplicate,
    );
    let packet = s1_packet(8);
    let wire = original_remote.encrypt_to_bytes(&packet).unwrap();
    let still_original = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_original.packet.packet, packet);
    assert_eq!(
        still_original.source.authorized_peer_lifecycle(),
        Some(old_life)
    );

    let (mut legacy_remote, legacy_local) = establish_sessions();
    let (_upgrade_remote, upgrade_local) = establish_sessions();
    let (legacy_transport, _legacy_rx) = WireGuardTransport::new();
    legacy_transport
        .stage_responder_session("peer-a", "legacy".to_string(), legacy_local)
        .await;
    assert_eq!(
        legacy_transport
            .stage_responder_session_for_lifecycle(
                "peer-a",
                "legacy".to_string(),
                upgrade_local,
                current_life,
            )
            .await,
        ResponderSessionStage::StaleDuplicate,
    );
    let packet = s1_packet(9);
    let wire = legacy_remote.encrypt_to_bytes(&packet).unwrap();
    let legacy = legacy_transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(legacy.packet.packet, packet);
    assert_eq!(legacy.source.authorized_peer_lifecycle(), None);
}

#[tokio::test]
async fn s1_exact_cached_restage_and_initial_commit_keep_original_scope() {
    let (peers, info, original_life) = s1_peer_scope_owner().await;
    let (_old_remote, old_local) = establish_sessions();
    let (mut remote, local, cached_keys) = s1_establish_cached_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    transport.add_session("peer-a", old_local).await;
    transport
        .stage_responder_session_for_lifecycle("peer-a", "cached".to_string(), local, original_life)
        .await;
    transport.commit_responder_session("peer-a", "cached").await;
    transport
        .expire_pending_responder_for_test("peer-a", "cached")
        .await;
    assert!(
        !transport
            .session_status("peer-a")
            .await
            .has_pending_responder
    );
    assert_eq!(
        transport
            .restage_cached_responder_session_for_lifecycle(
                "peer-a",
                "cached".to_string(),
                TransportSession::new(cached_keys),
                original_life,
            )
            .await,
        ResponderSessionStage::Staged { had_active: true },
    );
    let _current_life = s1_readd_peer(&peers, &info).await;
    let packet = s1_packet(10);
    let wire = remote.encrypt_to_bytes(&packet).unwrap();
    let restaged = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        restaged.packet.packet, packet,
        "same cached handshake keys must really decrypt"
    );
    assert_eq!(
        restaged.source.authorized_peer_lifecycle(),
        Some(original_life)
    );

    // A distinct initial responder commit moves the whole slot before decrypt.
    let (mut initial_remote, initial_local) = establish_sessions();
    let (initial, _initial_rx) = WireGuardTransport::new();
    initial
        .stage_responder_session_for_lifecycle(
            "peer-a",
            "initial".to_string(),
            initial_local,
            original_life,
        )
        .await;
    assert_eq!(
        initial.commit_responder_session("peer-a", "initial").await,
        ResponderSessionCommit::ActivatedInitial,
    );
    let packet = s1_packet(11);
    let wire = initial_remote.encrypt_to_bytes(&packet).unwrap();
    let committed = initial
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.packet.packet, packet);
    assert_eq!(
        committed.source.authorized_peer_lifecycle(),
        Some(original_life)
    );
}

#[tokio::test]
async fn s1_structured_rollback_preserves_key_replay_state_life_and_legacy_unknown() {
    let (peers, info, original_life) = s1_peer_scope_owner().await;
    let (mut old_remote, old_local) = establish_sessions();
    let (_new_remote, new_local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    s1_install_authorized(
        &transport,
        Some("old-key-token".to_string()),
        old_local,
        original_life,
    )
    .await;
    let packet = s1_packet(12);
    let consumed_wire = old_remote.encrypt_to_bytes(&packet).unwrap();
    let before = transport
        .decrypt_inbound_with_source(&consumed_wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.packet.packet, packet);
    let replacement_life = s1_readd_peer(&peers, &info).await;
    let rollback = transport
        .replace_session_for_lifecycle("peer-a", new_local, replacement_life)
        .await;
    assert!(rollback.is_some());
    transport
        .restore_session_rollback("peer-a", rollback)
        .await
        .unwrap();
    assert!(matches!(
        transport.decrypt_inbound_with_source(&consumed_wire).await,
        Err(InboundDecryptError::Decrypt(
            WireGuardError::ReplayDetected(0)
        ))
    ));
    let packet = s1_packet(13);
    let wire = old_remote.encrypt_to_bytes(&packet).unwrap();
    let restored = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        restored.packet.packet, packet,
        "the actual old key must be restored"
    );
    assert_eq!(
        restored.source.authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_ne!(
        restored.source.authorized_peer_lifecycle(),
        Some(replacement_life)
    );
    assert_ne!(
        restored.source.session_instance(),
        before.source.session_instance()
    );
    assert_eq!(
        transport
            .active_responder_token_for_test("peer-a")
            .await
            .as_deref(),
        Some("old-key-token")
    );

    let (_third_remote, third_local) = establish_sessions();
    let raw_legacy_rollback = transport.replace_session("peer-a", third_local).await;
    transport
        .restore_session("peer-a", raw_legacy_rollback)
        .await;
    let packet = s1_packet(14);
    let wire = old_remote.encrypt_to_bytes(&packet).unwrap();
    let legacy = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(legacy.packet.packet, packet);
    assert_eq!(
        legacy.source.authorized_peer_lifecycle(),
        None,
        "raw legacy rollback cannot retain qualification"
    );
}

#[tokio::test]
async fn s1_rekey_overlap_expiry_discard_and_remove_follow_real_slots() {
    let (peers, info, old_life) = s1_peer_scope_owner().await;
    let (mut old_remote, old_local) = establish_sessions();
    let (mut current_remote, current_local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    s1_install_authorized(&transport, None, old_local, old_life).await;
    let current_life = s1_readd_peer(&peers, &info).await;
    s1_install_authorized(&transport, None, current_local, current_life).await;
    let packet = s1_packet(15);
    let wire = old_remote.encrypt_to_bytes(&packet).unwrap();
    let previous = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(previous.packet.packet, packet);
    assert!(previous.source.is_previous_session());
    assert_eq!(previous.source.authorized_peer_lifecycle(), Some(old_life));
    assert_eq!(
        transport
            .session_instance_state("peer-a", previous.source.session_instance())
            .await,
        (true, false)
    );
    let packet = s1_packet(16);
    let wire = current_remote.encrypt_to_bytes(&packet).unwrap();
    let current = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.packet.packet, packet);
    assert!(!current.source.is_previous_session());
    assert_eq!(
        current.source.authorized_peer_lifecycle(),
        Some(current_life)
    );
    transport.expire_previous_session_for_test("peer-a").await;
    let expired_wire = old_remote.encrypt_to_bytes(&s1_packet(17)).unwrap();
    assert!(transport
        .decrypt_inbound_with_source(&expired_wire)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        transport
            .session_instance_state("peer-a", previous.source.session_instance())
            .await,
        (false, false)
    );

    let (mut discarded_remote, discarded_local) = establish_sessions();
    transport
        .stage_responder_session_for_lifecycle(
            "peer-a",
            "discarded".to_string(),
            discarded_local,
            current_life,
        )
        .await;
    assert!(
        transport
            .discard_responder_session("peer-a", "discarded")
            .await
    );
    let wire = discarded_remote.encrypt_to_bytes(&s1_packet(18)).unwrap();
    assert!(transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .is_none());
    let (_retry_remote, retry_local) = establish_sessions();
    assert_eq!(
        transport
            .restage_cached_responder_session_for_lifecycle(
                "peer-a",
                "discarded".to_string(),
                retry_local,
                current_life,
            )
            .await,
        ResponderSessionStage::StaleDuplicate,
    );
    transport.remove_session("peer-a").await;
    let wire = current_remote.encrypt_to_bytes(&s1_packet(19)).unwrap();
    assert!(transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        transport
            .session_instance_state("peer-a", current.source.session_instance())
            .await,
        (false, false)
    );
}

#[tokio::test]
async fn s1_rollback_rejects_cross_peer_and_owner_before_locks_and_allows_original_retry() {
    let (peers, info, original_life) = s1_peer_scope_owner().await;
    let (mut old_remote, old_local) = establish_sessions();
    let (mut replacement_remote, replacement_local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    s1_install_authorized(&transport, None, old_local, original_life).await;
    let original_packet = s1_packet(20);
    let consumed_old_wire = old_remote.encrypt_to_bytes(&original_packet).unwrap();
    let original = transport
        .decrypt_inbound_with_source(&consumed_old_wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.packet.packet, original_packet);
    let replacement_life = s1_readd_peer(&peers, &info).await;
    let rollback = transport
        .replace_session_for_lifecycle("peer-a", replacement_local, replacement_life)
        .await
        .expect("original key must be captured");

    let mut other_info = info.clone();
    other_info.node_id = "peer-b".to_string();
    other_info.virtual_ip = "10.20.0.3".to_string();
    peers.add_peer(&other_info).await;
    let other_life = peers.peer_session_generation_sync("peer-b").unwrap();
    let (mut other_peer_remote, other_peer_local) = establish_sessions();
    let other_emit = transport.outbound_emit_lock("peer-b").await;
    let other_guard = other_emit.lock().await;
    transport
        .install_active_session_for_lifecycle_locked("peer-b", None, other_peer_local, other_life)
        .await;
    let registry_guard = transport.sessions.lock().await;
    let mut wrong_peer = Box::pin(transport.restore_session_rollback("peer-b", Some(rollback)));
    let rejection = match futures_util::poll!(&mut wrong_peer) {
        std::task::Poll::Ready(Err(rejection)) => rejection,
        _ => panic!("cross-peer rejection must precede held emit and registry locks"),
    };
    assert_eq!(
        rejection.reason(),
        SessionRollbackIdentityMismatch::PeerMismatch
    );
    let rollback = rejection.into_rollback();
    drop(wrong_peer);
    drop(registry_guard);
    drop(other_guard);
    let other_packet = s1_packet(21);
    let wire = other_peer_remote.encrypt_to_bytes(&other_packet).unwrap();
    let other_peer = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(other_peer.packet.peer_id, "peer-b");
    assert_eq!(
        other_peer.packet.packet, other_packet,
        "rejection must leave peer-b's real key intact"
    );
    assert_eq!(
        other_peer.source.authorized_peer_lifecycle(),
        Some(other_life)
    );
    let replacement_packet = s1_packet(22);
    let wire = replacement_remote
        .encrypt_to_bytes(&replacement_packet)
        .unwrap();
    let replacement = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        replacement.packet.packet, replacement_packet,
        "rejection must leave source replacement intact"
    );
    assert_eq!(
        replacement.source.authorized_peer_lifecycle(),
        Some(replacement_life)
    );

    // Same peer string/current lifecycle is insufficient: another real map owner
    // must reject the untouched original token before acquiring either lock.
    let (mut other_owner_remote, other_owner_local) = establish_sessions();
    let (other_owner, _other_rx) = WireGuardTransport::new();
    s1_install_authorized(&other_owner, None, other_owner_local, replacement_life).await;
    let owner_emit = other_owner.outbound_emit_lock("peer-a").await;
    let owner_guard = owner_emit.lock().await;
    let owner_registry_guard = other_owner.sessions.lock().await;
    let mut wrong_owner = Box::pin(other_owner.restore_session_rollback("peer-a", Some(rollback)));
    let rejection = match futures_util::poll!(&mut wrong_owner) {
        std::task::Poll::Ready(Err(rejection)) => rejection,
        _ => panic!("cross-owner rejection must precede held emit and registry locks"),
    };
    assert_eq!(
        rejection.reason(),
        SessionRollbackIdentityMismatch::OwnerMismatch
    );
    let rollback = rejection.into_rollback();
    drop(wrong_owner);
    drop(owner_registry_guard);
    drop(owner_guard);
    let other_owner_packet = s1_packet(23);
    let wire = other_owner_remote
        .encrypt_to_bytes(&other_owner_packet)
        .unwrap();
    let unaffected = other_owner
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        unaffected.packet.packet, other_owner_packet,
        "rejection must preserve the other owner's real key"
    );
    assert!(unaffected.source.belongs_to(&other_owner));
    assert!(!unaffected.source.belongs_to(&transport));
    assert_eq!(
        unaffected.source.authorized_peer_lifecycle(),
        Some(replacement_life)
    );

    transport
        .restore_session_rollback("peer-a", Some(rollback))
        .await
        .unwrap();
    assert!(matches!(
        transport
            .decrypt_inbound_with_source(&consumed_old_wire)
            .await,
        Err(InboundDecryptError::Decrypt(
            WireGuardError::ReplayDetected(0)
        ))
    ));
    let restored_packet = s1_packet(24);
    let wire = old_remote.encrypt_to_bytes(&restored_packet).unwrap();
    let restored = transport
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        restored.packet.packet, restored_packet,
        "returned token must restore the actual original key"
    );
    assert_eq!(restored.source.peer_id(), "peer-a");
    assert!(restored.source.belongs_to(&transport));
    assert!(!restored.source.belongs_to(&other_owner));
    assert_eq!(
        restored.source.authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_ne!(
        restored.source.authorized_peer_lifecycle(),
        Some(replacement_life)
    );
    assert_ne!(
        restored.source.session_instance(),
        original.source.session_instance()
    );
}
