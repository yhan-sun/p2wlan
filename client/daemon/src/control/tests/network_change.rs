use super::*;

fn hint(generation: u64, identity: &str) -> AndroidNetworkChangeHint {
    AndroidNetworkChangeHint {
        kotlin_network_generation: generation,
        network_identity_hash: identity.into(),
    }
}

#[test]
fn burst_has_one_wakeup_and_registration_absorbs_the_latest_edge() {
    let changes = ControlNetworkChanges::default();
    assert!(changes.observe(hint(40, "old-service")));
    assert!(!changes.observe(hint(1, "new-service")));
    let (edge, changed) = changes.begin_registration();
    assert!(changed);
    let ControlNetworkEdge::Android(latest_hint) = edge.as_ref().unwrap().as_ref() else {
        panic!("expected the latest Android edge");
    };
    assert_eq!(latest_hint.network_identity_hash, "new-service");
    let published = std::cell::Cell::new(false);
    assert!(changes.commit_if_current(&edge, || published.set(true)));
    assert!(published.get());
    assert!(
        changes.take_pending(true).is_none(),
        "the queued wakeup must not revoke the just-completed registration"
    );
    assert!(
        changes.observe(hint(2, "next-network")),
        "a subsequent genuine handover must wake the owner"
    );
}

#[tokio::test]
async fn superseding_edge_cancels_registration_and_fences_its_late_result() {
    let changes = ControlNetworkChanges::default();
    changes.observe(hint(9, "previous"));
    let (edge, _) = changes.begin_registration();
    let mut cancelled = Box::pin(changes.changed_since(&edge));
    assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
    // Same generation/hash is still a different accepted publication; JNI
    // owns deduplication and a different service may restart these values.
    changes.observe(hint(9, "previous"));
    assert!(futures_util::poll!(cancelled.as_mut()).is_ready());
    assert!(!changes.commit_if_current(&edge, || panic!("stale auth published")));
    let (current, changed) = changes.begin_registration();
    assert!(changed);
    assert!(changes.commit_if_current(&current, || {}));
}

#[tokio::test]
async fn edge_before_notification_registration_is_not_a_lost_wakeup() {
    let changes = ControlNetworkChanges::default();
    let initial = changes.snapshot();
    changes.observe(hint(1, "new"));
    assert!(futures_util::poll!(Box::pin(changes.changed_since(&initial))).is_ready());
}

#[tokio::test]
async fn confirmed_route_cancels_registration_and_fences_its_late_result() {
    let changes = Arc::new(ControlNetworkChanges::default());
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let notifier = ControlRouteChangeNotifier::new(changes.clone(), commands);
    let (edge, _) = changes.begin_registration();
    let (auth, _auth_rx) = watch::channel(Some(current_auth()));
    let clock = ServerClockEstimate::default();
    let work = changes.during_registration(&edge, &auth, &clock, std::future::pending::<()>());
    tokio::pin!(work);
    assert!(futures_util::poll!(&mut work).is_pending());
    notifier.notify();
    notifier.notify();
    assert_eq!(work.await, None);
    assert!(auth.borrow().is_none());
    assert!(!changes.commit_if_current(&edge, || panic!("stale route registered")));
    let (current, changed) = changes.begin_registration();
    assert!(changed);
    assert!(!current.as_ref().unwrap().requires_http_rebuild());
    assert!(matches!(
        command_rx.try_recv(),
        Ok(ControlCommand::NetworkChanged(_))
    ));
    assert!(
        command_rx.is_empty(),
        "route bursts share one queued wakeup"
    );
    assert!(changes.take_pending(true).is_none());
    assert!(changes.commit_if_current(&current, || {}));
}

fn current_auth() -> CriticalControlAuth {
    CriticalControlAuth {
        accepted_peer_capabilities: PeerCapabilities::current(),
        base_url: "http://control.invalid".into(),
        token: "synthetic-credential".into(),
        self_node_id: "synthetic-node".into(),
        registration_seq: Some(7),
        signal_signing_identity: None,
    }
}

#[tokio::test]
async fn post_registration_state_writer_is_cancelled_and_cannot_republish_auth() {
    let changes = ControlNetworkChanges::default();
    changes.observe(hint(1, "old-network"));
    let (edge, _) = changes.begin_registration();
    let (auth, _auth_rx) = watch::channel(Some(current_auth()));
    let clock = ServerClockEstimate::default();
    let state = tokio::sync::RwLock::new(false);
    let reader = state.read().await;
    let mut work = Box::pin(changes.during_registration(&edge, &auth, &clock, state.write()));
    assert!(futures_util::poll!(work.as_mut()).is_pending());
    assert!(
        state.try_read().is_err(),
        "the real writer must already be queued"
    );
    changes.observe(hint(2, "new-network"));
    assert!(futures_util::poll!(work.as_mut()).is_ready());
    assert!(auth.borrow().is_none());
    assert!(state.try_read().is_ok());
    assert!(
        !changes.commit_registration_if_current(&edge, &auth, &clock, || {
            auth.send_replace(Some(current_auth()));
        })
    );
    assert!(auth.borrow().is_none());
    drop(reader);
}

#[tokio::test]
async fn network_change_revokes_auth_but_preserves_successful_credential_response() {
    let changes = ControlNetworkChanges::default();
    changes.observe(hint(1, "old-network"));
    let (edge, _) = changes.begin_registration();
    let (auth, _auth_rx) = watch::channel(Some(current_auth()));
    let clock = ServerClockEstimate::default();
    let (issued, result) = tokio::sync::oneshot::channel();
    let mut credential =
        Box::pin(changes.finish_registration_side_effect(&edge, &auth, &clock, result));
    assert!(futures_util::poll!(credential.as_mut()).is_pending());
    changes.observe(hint(2, "new-network"));
    assert!(futures_util::poll!(credential.as_mut()).is_pending());
    assert!(
        auth.borrow().is_none(),
        "old auth is revoked before the credential response completes"
    );
    issued.send("issued-once").unwrap();
    assert_eq!(credential.await.unwrap(), "issued-once");
    assert!(!changes
        .commit_registration_if_current(&edge, &auth, &clock, || panic!("old auth revived")));
    let (current, _) = changes.begin_registration();
    assert!(
        changes.commit_registration_if_current(&current, &auth, &clock, || {
            let mut registration = current_auth();
            registration.token = "issued-once".into();
            auth.send_replace(Some(registration));
        })
    );
    assert_eq!(auth.borrow().as_ref().unwrap().token, "issued-once");
}
