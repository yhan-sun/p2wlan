/// Local preparation retries do not transmit handshakes. Network retransmits
/// remain owned by the pending-handshake transaction and its existing limits.
const MAX_MAINTENANCE_RETRIES: usize = 1024;
const MAINTENANCE_CLEANUP_TTL: Duration = Duration::from_secs(60);
const MAINTENANCE_CLEANUP_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MaintenanceRetryIdentity {
    network_generation: u64,
    peer_session_generation: PeerSessionGeneration,
    active_session_instance: Option<u64>,
}

struct MaintenancePreparationRetry {
    identity: MaintenanceRetryIdentity,
    not_before: Instant,
    hard_deadline: Option<Instant>,
    attempt: u32,
    reason: &'static str,
}

#[derive(Default)]
struct MaintenancePreparationRetries {
    entries: HashMap<String, MaintenancePreparationRetry>,
}

impl MaintenancePreparationRetries {
    fn next_deadline(&self) -> Option<Instant> {
        self.entries.values().map(|entry| entry.not_before).min()
    }

    fn ready(&mut self, peer_id: &str, identity: MaintenanceRetryIdentity, now: Instant) -> bool {
        match self.entries.get(peer_id) {
            Some(entry) if entry.identity == identity => now >= entry.not_before,
            Some(_) => {
                self.entries.remove(peer_id);
                true
            }
            None => true,
        }
    }

    fn remove(&mut self, peer_id: &str) {
        self.entries.remove(peer_id);
    }

    fn retain_current(&mut self, peers: &PeerManager) {
        let generation = peers.current_network_generation_sync();
        self.entries.retain(|peer_id, retry| {
            retry.identity.network_generation == generation
                && peers
                    .peer_session_is_current_sync(peer_id, retry.identity.peer_session_generation)
        });
    }

    fn schedule(
        &mut self,
        peer_id: &str,
        identity: MaintenanceRetryIdentity,
        hard_deadline: Option<Instant>,
        reason: &'static str,
        now: Instant,
    ) {
        if !self.entries.contains_key(peer_id) && self.entries.len() >= MAX_MAINTENANCE_RETRIES {
            debug!(
                reason_code = "maintenance_retry_capacity",
                "Maintenance scan remains the retry backstop"
            );
            return;
        }
        let entry =
            self.entries
                .entry(peer_id.to_string())
                .or_insert(MaintenancePreparationRetry {
                    identity,
                    not_before: now,
                    hard_deadline,
                    attempt: 0,
                    reason,
                });
        if entry.identity != identity {
            *entry = MaintenancePreparationRetry {
                identity,
                not_before: now,
                hard_deadline,
                attempt: 0,
                reason,
            };
        }
        // A repeated snapshot may shorten a deadline, never renew the old key.
        entry.hard_deadline = match (entry.hard_deadline, hard_deadline) {
            (Some(old), Some(current)) => Some(old.min(current)),
            (old, current) => old.or(current),
        };
        let reason_changed = entry.reason != reason;
        entry.reason = reason;
        entry.attempt = entry.attempt.saturating_add(1);
        let remaining = entry
            .hard_deadline
            .map(|deadline| deadline.saturating_duration_since(now));
        let urgent = remaining
            .is_some_and(|remaining| !remaining.is_zero() && remaining <= Duration::from_secs(5));
        let base_ms = if urgent {
            50
        } else {
            50u64 << entry.attempt.saturating_sub(1).min(4)
        };
        let peer_fingerprint = crate::transport::wire_fingerprint(peer_id.as_bytes());
        let jitter_ms = peer_fingerprint.wrapping_add(u64::from(entry.attempt) * 17) % 51;
        let delay = Duration::from_millis(base_ms + jitter_ms);
        entry.not_before = now + delay;
        if entry.attempt.is_power_of_two() || reason_changed {
            debug!(
                event = "maintenance_preparation_retry_scheduled",
                peer_fp = peer_fingerprint,
                reason_code = reason,
                attempt = entry.attempt,
                retry_ms = delay.as_millis() as u64,
                remaining_ms = remaining.map(|value| value.as_millis() as u64),
                network_generation = identity.network_generation,
                peer_session_generation = identity.peer_session_generation.value(),
                active_session_instance = identity.active_session_instance,
                "Handshake preparation deferred without consuming a network attempt"
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum MaintenanceBindingOutcome {
    Staged,
    Retry(&'static str),
    Cancel(&'static str),
}

fn try_stage_maintenance_probe_binding(
    peers: &PeerManager,
    peer_id: &str,
    reservation: &HandshakeStartReservation,
    session_id: &str,
) -> MaintenanceBindingOutcome {
    let epoch_gate = peers.network_epoch_gate();
    let Ok(_epoch_guard) = epoch_gate.try_lock() else {
        return MaintenanceBindingOutcome::Retry("network_epoch_contended");
    };
    if *reservation.cancellation.borrow()
        || peers.current_network_generation_sync() != reservation.network_generation
        || !peers.peer_session_is_current_sync(peer_id, reservation.peer_session_generation)
    {
        return MaintenanceBindingOutcome::Cancel("stale_lifecycle");
    }
    match peers.try_stage_probe_session_binding(
        peer_id,
        session_id.to_string(),
        Some(session_id.to_string()),
        None,
        false,
    ) {
        Some(ProbeBindingStage::Staged) => MaintenanceBindingOutcome::Staged,
        None => MaintenanceBindingOutcome::Retry("connections_contended"),
        Some(ProbeBindingStage::Busy) => MaintenanceBindingOutcome::Retry("binding_capacity"),
        Some(ProbeBindingStage::PeerMissing) => MaintenanceBindingOutcome::Cancel("peer_missing"),
        Some(ProbeBindingStage::ReplayableDuplicate) => {
            MaintenanceBindingOutcome::Cancel("binding_duplicate")
        }
        Some(ProbeBindingStage::StaleDuplicate) => {
            MaintenanceBindingOutcome::Cancel("binding_stale")
        }
    }
}

/// An existing encrypted relay session can rekey without UDP candidates,
/// even before a UDP snapshot exists. Only lock contention defers this read.
/// First-session candidate gathering continues to use its readiness fence.
fn try_cached_maintenance_rekey_candidates(
    snapshot: &RwLock<Option<CandidateSnapshotLease>>,
) -> Option<(Vec<String>, HashMap<String, String>)> {
    let snapshot = snapshot.try_read().ok()?;
    Some(snapshot.as_ref().map_or_else(
        || (Vec::new(), HashMap::new()),
        |snapshot| {
            (
                snapshot.candidates.clone(),
                snapshot.candidate_sources.clone(),
            )
        },
    ))
}

struct MaintenanceProbeCleanup {
    peer_session_generation: PeerSessionGeneration,
    expires_at: Instant,
}

#[derive(Default)]
struct MaintenanceProbeCleanups {
    entries: HashMap<(String, String), MaintenanceProbeCleanup>,
    not_before: Option<Instant>,
}

fn try_cleanup_maintenance_probe_binding(
    peers: &PeerManager,
    peer_id: &str,
    token: &str,
    peer_session_generation: PeerSessionGeneration,
) -> bool {
    let epoch_gate = peers.network_epoch_gate();
    let Ok(_epoch_guard) = epoch_gate.try_lock() else {
        return false;
    };
    if !peers.peer_session_is_current_sync(peer_id, peer_session_generation) {
        return true;
    }
    // Both removed and already promoted are terminal. Never remove an active key.
    peers
        .try_discard_pending_probe_session_binding(peer_id, token)
        .is_some()
}

impl MaintenanceProbeCleanups {
    fn discard_or_defer(
        &mut self,
        peers: &PeerManager,
        peer_id: &str,
        token: &str,
        peer_session_generation: PeerSessionGeneration,
    ) {
        if try_cleanup_maintenance_probe_binding(peers, peer_id, token, peer_session_generation) {
            return;
        }
        if self.entries.len() >= MAX_MAINTENANCE_RETRIES {
            // The authoritative binding has its own bounded TTL even when the
            // best-effort eager cleanup ledger is at capacity.
            debug!(
                reason_code = "maintenance_cleanup_capacity",
                "Probe binding cleanup left to its bounded TTL"
            );
            return;
        }
        let now = Instant::now();
        self.entries
            .entry((peer_id.to_string(), token.to_string()))
            .or_insert(MaintenanceProbeCleanup {
                peer_session_generation,
                expires_at: now + MAINTENANCE_CLEANUP_TTL,
            });
        self.not_before = Some(self.not_before.map_or(now, |deadline| deadline.min(now)));
    }

    fn drain(&mut self, peers: &PeerManager, now: Instant) {
        self.entries.retain(|(peer_id, token), entry| {
            now < entry.expires_at
                && !try_cleanup_maintenance_probe_binding(
                    peers,
                    peer_id,
                    token,
                    entry.peer_session_generation,
                )
        });
        self.not_before = (!self.entries.is_empty()).then_some(now + MAINTENANCE_CLEANUP_INTERVAL);
    }
}

#[cfg(test)]
mod maintenance_retry_tests {
    use super::*;

    async fn fixture() -> (PeerManager, control::PeerInfo, MaintenanceRetryIdentity) {
        let manager =
            PeerManager::new(Config::generate_default("http://127.0.0.1:1", "net1").unwrap());
        let peer = control::PeerInfo {
            node_id: "maintenance-peer".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(NodeIdentity::generate().public_key()),
            endpoint: "192.0.2.1:51820".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        };
        manager.add_peer(&peer).await;
        let identity = MaintenanceRetryIdentity {
            network_generation: manager.current_network_generation_sync(),
            peer_session_generation: manager.peer_session_generation_sync(&peer.node_id).unwrap(),
            active_session_instance: Some(1),
        };
        (manager, peer, identity)
    }

    #[tokio::test]
    async fn maintenance_retry_is_due_before_ten_second_scan_and_kicks_do_not_bypass_backoff() {
        let (_, peer, identity) = fixture().await;
        let now = Instant::now();
        let mut retries = MaintenancePreparationRetries::default();
        retries.schedule(
            &peer.node_id,
            identity,
            Some(now + Duration::from_secs(40)),
            "connections_contended",
            now,
        );
        let due = retries.next_deadline().unwrap();
        assert!(due > now);
        assert!(due <= now + Duration::from_millis(100));
        for _ in 0..100 {
            assert!(!retries.ready(&peer.node_id, identity, now));
        }
        assert!(retries.ready(&peer.node_id, identity, due));
    }

    #[tokio::test]
    async fn maintenance_retry_preserves_deadline_and_accelerates_before_hard_expiry() {
        let (_, peer, identity) = fixture().await;
        let start = Instant::now();
        let deadline = start + Duration::from_secs(30);
        let mut retries = MaintenancePreparationRetries::default();
        for attempt in 0..20 {
            let now = start + Duration::from_secs(attempt);
            retries.schedule(
                &peer.node_id,
                identity,
                Some(now + Duration::from_secs(30)),
                "connections_contended",
                now,
            );
            assert_eq!(retries.entries[&peer.node_id].hard_deadline, Some(deadline));
            let delay = retries.next_deadline().unwrap() - now;
            assert!(delay >= Duration::from_millis(50));
            assert!(delay <= Duration::from_millis(850));
        }
        let urgent = deadline - Duration::from_secs(4);
        retries.schedule(
            &peer.node_id,
            identity,
            Some(deadline),
            "connections_contended",
            urgent,
        );
        assert!(retries.next_deadline().unwrap() - urgent <= Duration::from_millis(100));
        retries.schedule(
            &peer.node_id,
            identity,
            Some(deadline),
            "connections_contended",
            deadline,
        );
        assert!(retries.next_deadline().unwrap() > deadline);
    }

    #[tokio::test]
    async fn maintenance_retry_replacement_session_does_not_inherit_old_backoff() {
        let (manager, peer, identity) = fixture().await;
        let now = Instant::now();
        let mut retries = MaintenancePreparationRetries::default();
        retries.schedule(
            &peer.node_id,
            identity,
            Some(now),
            "connections_contended",
            now,
        );
        let replacement = MaintenanceRetryIdentity {
            active_session_instance: Some(2),
            ..identity
        };
        assert!(retries.ready(&peer.node_id, replacement, now));
        assert!(retries.next_deadline().is_none());
        retries.schedule(
            &peer.node_id,
            identity,
            Some(now),
            "connections_contended",
            now,
        );
        manager.remove_peer(&peer.node_id).await;
        manager.add_peer(&peer).await;
        retries.retain_current(&manager);
        assert!(retries.next_deadline().is_none());
    }

    #[tokio::test]
    async fn maintenance_cleanup_never_queues_a_writer_and_preserves_promoted_binding() {
        let (manager, peer, identity) = fixture().await;
        assert_eq!(
            manager
                .stage_probe_session_binding(
                    &peer.node_id,
                    "pending".to_string(),
                    Some("pending".to_string()),
                    None,
                    false
                )
                .await,
            ProbeBindingStage::Staged
        );
        let reader = manager.hold_connections_reader_for_test().await;
        let mut cleanups = MaintenanceProbeCleanups::default();
        cleanups.discard_or_defer(
            &manager,
            &peer.node_id,
            "pending",
            identity.peer_session_generation,
        );
        assert_eq!(cleanups.entries.len(), 1);
        let second_reader = tokio::time::timeout(
            Duration::from_millis(100),
            manager.hold_connections_reader_for_test(),
        )
        .await
        .expect("cleanup must not enqueue a writer ahead of another reader");
        drop(second_reader);
        drop(reader);
        cleanups.drain(&manager, Instant::now());
        assert!(cleanups.entries.is_empty());
        assert_eq!(
            manager
                .stage_probe_session_binding(
                    &peer.node_id,
                    "pending".to_string(),
                    Some("pending".to_string()),
                    None,
                    false
                )
                .await,
            ProbeBindingStage::Staged
        );
        assert!(
            manager
                .install_probe_session_binding(
                    &peer.node_id,
                    "pending".to_string(),
                    Some("pending".to_string()),
                    None
                )
                .await
        );
        cleanups.discard_or_defer(
            &manager,
            &peer.node_id,
            "pending",
            identity.peer_session_generation,
        );
        assert!(cleanups.entries.is_empty());
        assert!(!manager
            .try_discard_pending_probe_session_binding(&peer.node_id, "pending")
            .unwrap());
    }

    #[tokio::test]
    async fn maintenance_cleanup_cannot_delete_a_rejoined_peers_binding() {
        let (manager, peer, identity) = fixture().await;
        let reader = manager.hold_connections_reader_for_test().await;
        let mut cleanups = MaintenanceProbeCleanups::default();
        cleanups.discard_or_defer(
            &manager,
            &peer.node_id,
            "same-token",
            identity.peer_session_generation,
        );
        drop(reader);
        manager.remove_peer(&peer.node_id).await;
        manager.add_peer(&peer).await;
        assert_eq!(
            manager
                .stage_probe_session_binding(
                    &peer.node_id,
                    "same-token".to_string(),
                    Some("same-token".to_string()),
                    None,
                    false
                )
                .await,
            ProbeBindingStage::Staged
        );
        cleanups.drain(&manager, Instant::now());
        assert!(cleanups.entries.is_empty());
        assert_eq!(
            manager
                .stage_probe_session_binding(
                    &peer.node_id,
                    "same-token".to_string(),
                    Some("same-token".to_string()),
                    None,
                    false
                )
                .await,
            ProbeBindingStage::ReplayableDuplicate
        );
    }

    #[tokio::test]
    async fn maintenance_rekey_reads_snapshot_during_live_refresh_and_accepts_relay_only() {
        let daemon = Daemon::new(Config::generate_default("http://127.0.0.1:1", "net1").unwrap());
        let (candidates, sources) =
            try_cached_maintenance_rekey_candidates(&daemon.candidate_snapshot)
                .expect("an existing relay session must rekey without a UDP snapshot");
        assert!(candidates.is_empty() && sources.is_empty());
        daemon
            .publish_candidate_snapshot(Vec::new(), HashMap::new(), Vec::new())
            .await;
        let _refresh = daemon.candidate_refresh_lock.lock().await;
        let (candidates, sources) =
            try_cached_maintenance_rekey_candidates(&daemon.candidate_snapshot)
                .expect("relay-only rekey must not wait for STUN or the refresh lock");
        assert!(candidates.is_empty());
        assert!(sources.is_empty());
        let _writer = daemon.candidate_snapshot.write().await;
        assert!(try_cached_maintenance_rekey_candidates(&daemon.candidate_snapshot).is_none());
    }

    #[tokio::test]
    async fn maintenance_cleanup_capacity_and_ttl_do_not_grow_with_duplicate_work() {
        let (manager, peer, identity) = fixture().await;
        let reader = manager.hold_connections_reader_for_test().await;
        let mut cleanups = MaintenanceProbeCleanups::default();
        cleanups.discard_or_defer(
            &manager,
            &peer.node_id,
            "token-0",
            identity.peer_session_generation,
        );
        let first_expiry =
            cleanups.entries[&(peer.node_id.clone(), "token-0".to_string())].expires_at;
        for index in 0..MAX_MAINTENANCE_RETRIES + 10 {
            cleanups.discard_or_defer(
                &manager,
                &peer.node_id,
                &format!("token-{index}"),
                identity.peer_session_generation,
            );
        }
        assert_eq!(cleanups.entries.len(), MAX_MAINTENANCE_RETRIES);
        assert_eq!(
            cleanups.entries[&(peer.node_id.clone(), "token-0".to_string())].expires_at,
            first_expiry
        );
        cleanups.drain(&manager, Instant::now() + MAINTENANCE_CLEANUP_TTL);
        assert!(cleanups.entries.is_empty());
        assert!(cleanups.not_before.is_none());
        drop(reader);
    }
}

include!("handshake_maintenance_tests.rs");
