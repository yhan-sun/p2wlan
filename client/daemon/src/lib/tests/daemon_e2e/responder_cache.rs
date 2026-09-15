// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;

#[test]
fn responder_timestamp_floor_is_monotonic_and_scoped_to_static_identity() {
    let mut state = PendingHandshakeState::default();
    let first_key = [1u8; 32];
    let rotated_key = [2u8; 32];
    let first_timestamp = [3u8; 12];
    let newer_timestamp = [4u8; 12];

    assert!(state.commit_responder_timestamp("peer-a", first_key, first_timestamp));
    assert_eq!(
        state.responder_timestamp_floor("peer-a", &first_key),
        Some(first_timestamp)
    );
    assert!(!state.commit_responder_timestamp("peer-a", first_key, first_timestamp));
    assert!(state.commit_responder_timestamp("peer-a", first_key, newer_timestamp));
    assert_eq!(
        state.responder_timestamp_floor("peer-a", &rotated_key),
        None,
        "a verified static-key rotation must not inherit the old key's timestamp floor"
    );
    assert!(state.commit_responder_timestamp("peer-a", rotated_key, first_timestamp));
}

#[tokio::test]
async fn responder_cache_rejects_offer_after_peer_static_key_rotation() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-cache-key-rotation";
    let token = "rotated-static-key-token";
    let local_public = daemon.local_identity().unwrap().public_key();
    let old_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let old_public = old_identity.public_key();
    let new_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public && identity.public_key() != old_public {
            break identity;
        }
    };
    let new_public = new_identity.public_key();

    let mut old_initiator = HandshakeInitiator::new(old_identity, local_public, None);
    let initiation = old_initiator.create_initiation().unwrap();
    let initiation_bytes = initiation.to_bytes();
    let mut responder = HandshakeResponder::new(daemon.local_identity().unwrap(), None);
    let (response, keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let request_probe_public_key = hex::encode(DhKeyPair::generate().public_key());
    daemon.pending_handshakes.lock().cache_responder_handshake(
        peer_id,
        token,
        CachedResponderHandshake {
            lifecycle: ResponderHandshakeLifecycle {
                network_generation: 0,
                peer_session_generation: PeerSessionGeneration::for_test(1),
            },
            handshake_init: initiation_bytes.clone(),
            initiator_static_public_key: old_public,
            request_probe_ephemeral_public_key: Some(request_probe_public_key.clone()),
            response_bytes: response.to_bytes(),
            transport_keys: keys,
            response_probe_ephemeral_public_key: Some(hex::encode(
                DhKeyPair::generate().public_key(),
            )),
            probe_ephemeral_shared: Some([0x42; 32]),
            expires_at: Instant::now() + RESPONDER_HANDSHAKE_CACHE_TTL,
        },
    );
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(new_public),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let error = daemon
        .handle_peer_offer(
            peer_id,
            &[],
            &initiation_bytes,
            None,
            None,
            Some(token.to_string()),
            Some(request_probe_public_key),
        )
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("different handshake or Probe key material"));
    assert!(
        !daemon
            .transport
            .session_status(peer_id)
            .await
            .has_pending_responder
    );
}

#[tokio::test]
async fn expired_responder_cache_conflict_does_not_poison_active_token() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-expired-cache-conflict";
    let token = "same-active-token";

    let active_initiator_identity = NodeIdentity::generate();
    let active_responder_identity = NodeIdentity::generate();
    let mut active_initiator = HandshakeInitiator::new(
        active_initiator_identity,
        active_responder_identity.public_key(),
        None,
    );
    let active_initiation = active_initiator.create_initiation().unwrap();
    let mut active_responder = HandshakeResponder::new(active_responder_identity, None);
    let (active_response, _) = active_responder
        .consume_initiation_and_respond(&active_initiation)
        .unwrap();
    let active_keys = active_initiator.consume_response(&active_response).unwrap();
    daemon
        .transport
        .install_active_session(
            peer_id,
            Some(token.to_string()),
            TransportSession::new(active_keys),
        )
        .await;

    let local_public = daemon.local_identity().unwrap().public_key();
    let offer_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let offer_public = offer_identity.public_key();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(offer_public),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let mut offer_initiator = HandshakeInitiator::new(offer_identity, local_public, None);
    let offer_initiation = offer_initiator.create_initiation().unwrap();
    let offer_bytes = offer_initiation.to_bytes();
    let request_probe_public_key = hex::encode(DhKeyPair::generate().public_key());

    let mut expired_responder = HandshakeResponder::new(daemon.local_identity().unwrap(), None);
    let (expired_response, expired_keys) = expired_responder
        .consume_initiation_and_respond(&offer_initiation)
        .unwrap();
    daemon.pending_handshakes.lock().cache_responder_handshake(
        peer_id,
        token,
        CachedResponderHandshake {
            lifecycle: ResponderHandshakeLifecycle {
                network_generation: 0,
                peer_session_generation: PeerSessionGeneration::for_test(1),
            },
            handshake_init: offer_bytes.clone(),
            initiator_static_public_key: offer_public,
            request_probe_ephemeral_public_key: Some(request_probe_public_key.clone()),
            response_bytes: expired_response.to_bytes(),
            transport_keys: expired_keys,
            response_probe_ephemeral_public_key: Some(hex::encode(
                DhKeyPair::generate().public_key(),
            )),
            probe_ephemeral_shared: Some([9u8; 32]),
            expires_at: Instant::now(),
        },
    );

    for attempt in 0..2 {
        let error = daemon
            .handle_peer_offer(
                peer_id,
                &[],
                &offer_bytes,
                None,
                None,
                Some(token.to_string()),
                Some(request_probe_public_key.clone()),
            )
            .await
            .unwrap_err();
        let error = error.to_string();
        if attempt == 0 {
            assert!(
                error.contains("exact cached answer is unavailable"),
                "unexpected first conflict error: {error}"
            );
        } else {
            assert!(
                error.contains("replayed or out-of-order initiation timestamp")
                    || error.contains("refusing replayed WireGuard initiation"),
                "unexpected replay error: {error}"
            );
        }
        assert!(!daemon
            .pending_handshakes
            .lock()
            .responder_cache
            .contains_key(&(peer_id.to_string(), token.to_string())));
    }
}
