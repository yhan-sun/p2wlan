use super::*;

#[test]
fn opaque_route_hints_are_bounded_expire_and_refuse_collisions() {
    let mut hints = OpaqueProbeRouteHints::default();
    let now = Instant::now();
    assert!(hints.publish(
        (0..MAX_OPAQUE_PROBE_ROUTES)
            .map(|index| format!("{index:032x}"))
            .collect(),
        "peer",
        PeerSessionGeneration(1),
        now
    ));
    assert!(!hints.publish(
        vec!["f".repeat(32)],
        "overflow",
        PeerSessionGeneration(2),
        now
    ));
    assert!(!hints.publish(
        vec!["0".repeat(32)],
        "collision",
        PeerSessionGeneration(2),
        now
    ));
    assert!(hints.publish(
        vec!["f".repeat(32)],
        "replacement",
        PeerSessionGeneration(2),
        now + OPAQUE_PROBE_ROUTE_TTL
    ));
    assert_eq!(hints.entries.len(), 1);
}

#[test]
fn opaque_route_saturation_preserves_and_refreshes_active_when_pending_cannot_publish() {
    let mut hints = OpaqueProbeRouteHints::default();
    let now = Instant::now();
    let generation = PeerSessionGeneration(1);
    assert!(hints.publish(
        (0..MAX_OPAQUE_PROBE_ROUTES)
            .map(|index| format!("{index:032x}"))
            .collect(),
        "peer",
        generation,
        now
    ));
    let active = "0".repeat(32);
    assert!(!hints.publish(
        vec![active.clone(), "f".repeat(32)],
        "peer",
        generation,
        now + Duration::from_secs(1)
    ));
    assert_eq!(hints.entries[&active].generation, generation);
    assert!(hints.publish(
        vec![active.clone()],
        "peer",
        generation,
        now + Duration::from_secs(2)
    ));
    assert_eq!(hints.entries.len(), MAX_OPAQUE_PROBE_ROUTES);
    assert_eq!(
        hints.entries[&active].expires,
        now + Duration::from_secs(2) + OPAQUE_PROBE_ROUTE_TTL
    );
}

#[tokio::test]
async fn opaque_route_hints_follow_binding_roles_and_lifecycle_without_legacy_fallback() {
    let config = Config::generate_default("https://control.example.com", "test").unwrap();
    let manager = PeerManager::new(config);
    let control = crate::control::ControlClient::disabled_for_test();
    control.set_local_registration_for_test(Some(1), crate::control::PeerCapabilities::current());
    assert!(manager.bind_opaque_probe_registration(control.clone()));
    let identity = NodeIdentity::generate();
    let mut peer = PeerInfo {
        node_id: "route-peer".into(),
        public_key: hex::encode(identity.public_key()),
        virtual_ip: "10.20.0.2".into(),
        online: true,
        registration_seq: 1,
        capabilities: crate::control::PeerCapabilities::current(),
        ..Default::default()
    };
    manager.add_peer(&peer).await;
    assert_eq!(
        manager.opaque_probe_send_mode_for_peer(&peer.node_id).await,
        None
    );
    assert!(
        manager
            .set_probe_session_binding(&peer.node_id, Some("session-a".into()), Some([1; 32]))
            .await
    );
    let key = manager.probe_key_for_peer(&peer.node_id).await.unwrap();
    let label = p2pnet_nat::opaque_probe_identity(&key, &peer.node_id);
    assert_eq!(
        manager.opaque_probe_mode_for_peer(&peer.node_id).await,
        Some(true)
    );
    assert_eq!(
        manager.resolve_opaque_probe_peer(&label),
        Some(peer.node_id.clone())
    );
    assert_eq!(manager.resolve_opaque_probe_peer("unknown"), None);
    assert!(matches!(
        manager
            .stage_probe_session_binding(
                &peer.node_id,
                "pending".into(),
                Some("session-b".into()),
                Some([2; 32]),
                true
            )
            .await,
        ProbeBindingStage::Staged
    ));
    let candidate = manager
        .probe_key_candidates_for_peer(&peer.node_id)
        .await
        .into_iter()
        .find(|candidate| matches!(candidate.role, ProbeKeyRole::Pending { .. }))
        .unwrap();
    let pending_label = p2pnet_nat::opaque_probe_identity(&candidate.key, &peer.node_id);
    assert_eq!(
        manager.resolve_opaque_probe_peer(&pending_label),
        Some(peer.node_id.clone())
    );
    control.set_local_registration_for_test(Some(1), crate::control::PeerCapabilities::default());
    assert_eq!(
        manager.opaque_probe_mode_for_peer(&peer.node_id).await,
        None
    );
    control.set_local_registration_for_test(Some(2), crate::control::PeerCapabilities::current());
    assert_eq!(
        manager.opaque_probe_mode_for_peer(&peer.node_id).await,
        Some(true)
    );
    peer.capabilities.probe_opaque_ids_v1 = false;
    manager.add_peer(&peer).await;
    assert_eq!(
        manager.opaque_probe_mode_for_peer(&peer.node_id).await,
        None,
        "same-registration capability revocation must not expose stable IDs"
    );
    manager.remove_peer(&peer.node_id).await;
    assert_eq!(manager.resolve_opaque_probe_peer(&label), None);
    assert_eq!(manager.resolve_opaque_probe_peer(&pending_label), None);
}
