#[cfg(test)]
pub(crate) struct PeerMembershipPublishTestGate {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}

#[cfg(test)]
impl PeerMembershipPublishTestGate {
    fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }
}

#[cfg(test)]
type PeerMembershipPublishTestGateSlot =
    std::sync::Mutex<Option<(String, Arc<PeerMembershipPublishTestGate>)>>;

#[cfg(test)]
fn peer_membership_publish_test_gate_slot() -> &'static PeerMembershipPublishTestGateSlot {
    static SLOT: std::sync::OnceLock<PeerMembershipPublishTestGateSlot> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
pub(crate) fn install_peer_membership_publish_test_gate(
    peer_id: &str,
) -> Arc<PeerMembershipPublishTestGate> {
    let gate = Arc::new(PeerMembershipPublishTestGate::new());
    *peer_membership_publish_test_gate_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some((peer_id.to_string(), gate.clone()));
    gate
}

#[cfg(test)]
async fn pause_after_peer_membership_publish_for_test(peer_id: &str) {
    let gate = {
        let mut installed = peer_membership_publish_test_gate_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if installed
            .as_ref()
            .is_some_and(|(expected, _)| expected == peer_id)
        {
            installed.take().map(|(_, gate)| gate)
        } else {
            None
        }
    };
    if let Some(gate) = gate {
        gate.reached.notify_one();
        gate.release.notified().await;
    }
}

impl PeerManager {
    async fn lock_peer_update_resources<'a>(
        &'a self,
        trace: &mut PeerUpdateLockTrace<'_>,
    ) -> (
        tokio::sync::MutexGuard<'a, ()>,
        tokio::sync::RwLockWriteGuard<'a, HashMap<String, PeerConnection>>,
    ) {
        loop {
            let epoch_guard = match self.network_epoch_gate.try_lock() {
                Ok(guard) => guard,
                Err(_) => {
                    trace.wait_started(
                        PeerUpdateLockResource::NetworkEpochGate,
                        "mutex_wait",
                        "none",
                    );
                    let guard = self.network_epoch_gate.lock().await;
                    trace.acquired(PeerUpdateLockResource::NetworkEpochGate);
                    guard
                }
            };
            match self.connections.try_write() {
                Ok(connections) => {
                    trace.acquired(PeerUpdateLockResource::NetworkEpochGate);
                    trace.acquired(PeerUpdateLockResource::ConnectionsWrite);
                    return (epoch_guard, connections);
                }
                Err(_) => {
                    drop(epoch_guard);
                    trace.released(PeerUpdateLockResource::NetworkEpochGate);
                    trace.wait_started(
                        PeerUpdateLockResource::ConnectionsWrite,
                        "fair_writer_queue_probe",
                        "none",
                    );
                    let queue_probe = self.connections.write().await;
                    trace.queue_probe_acquired(PeerUpdateLockResource::ConnectionsWrite);
                    drop(queue_probe);
                    trace.queue_probe_released(PeerUpdateLockResource::ConnectionsWrite);
                }
            }
        }
    }
}

impl PeerManager {
    /// Add or update a peer from control plane info.
    pub async fn add_peer(&self, info: &PeerInfo) -> PeerUpdate {
        self.add_peer_with_signal_context(info, None).await
    }

    pub(crate) async fn add_peer_with_signal_context(
        &self,
        info: &PeerInfo,
        signal_context: Option<(&str, Option<u64>, &str)>,
    ) -> PeerUpdate {
        #[cfg(test)]
        self.notify_peer_add_wait_started_for_test();
        let mut lock_trace = PeerUpdateLockTrace::new(
            self,
            &info.node_id,
            self.current_network_generation_sync(),
            self.peer_session_generation_sync(&info.node_id)
                .map(|generation| generation.value()),
            signal_context,
        );
        // Control-plane incarnation updates are another writer of the same
        // relay/session state that network handover invalidates. Serialize
        // the generation snapshot and the connection mutation as one epoch
        // transaction; otherwise a public-key/session reset could be
        // published immediately before an old ACK commits.
        let (epoch_guard, mut conns) = self.lock_peer_update_resources(&mut lock_trace).await;
        let generation = self.current_network_generation_sync();
        // Un-quarantine evidence is computed under the connection lock but the
        // quarantine map is re-opened only AFTER the lock is dropped:
        // `unquarantine_peer` records a diagnostics event that re-locks the
        // connection map, so awaiting it while holding the write guard would
        // deadlock.
        let mut unquarantine_after_lock: Option<&'static str> = None;
        let mut cancel_heartbeat_after_lock = false;
        let mut revoke_relay_after_lock = false;
        let mut clear_hard_hard_after_lock = false;
        let mut ip_map = match self.ip_to_node.try_write() {
            Ok(ip_map) => {
                lock_trace.acquired(PeerUpdateLockResource::IpToNodeWrite);
                ip_map
            }
            Err(_) => {
                lock_trace.wait_started(
                    PeerUpdateLockResource::IpToNodeWrite,
                    "fair_writer_queue",
                    "network_epoch_gate,connections_write",
                );
                let ip_map = self.ip_to_node.write().await;
                lock_trace.acquired(PeerUpdateLockResource::IpToNodeWrite);
                ip_map
            }
        };

        let is_new = !conns.contains_key(&info.node_id);

        let conn = conns
            .entry(info.node_id.clone())
            .or_insert_with(|| PeerConnection::new(&info.node_id, &info.virtual_ip));
        // Keep the synchronous Direct-set mirror attached to every connection
        // so its `transition` keeps the UDP eviction's nonevictable set fresh.
        conn.attach_direct_cache(self.direct_peers.clone());
        conn.attach_direct_pair_cache(self.direct_commit_pair_mirror.clone());
        conn.attach_committed_business_path_cache(
            self.committed_business_paths.clone(),
            self.committed_business_path_change_tx.clone(),
        );
        conn.attach_telemetry_hub(self.telemetry_hub.clone());

        let old_virtual_ip = conn.virtual_ip.clone();
        let old_public_key = conn.public_key.clone();
        let old_signaled_endpoint = conn.signaled_endpoint;
        let old_online = conn.online;
        let old_device_name = conn.device_name.clone();
        let old_app_version = conn.app_version.clone();
        let old_nat_type = conn.nat_type.clone();
        let old_last_seen = conn.last_seen;
        let old_remote_relay_rtt_ms = conn.remote_relay_rtt_ms;
        let virtual_ip_changed = !is_new && old_virtual_ip != info.virtual_ip;
        let public_key_changed = !is_new && old_public_key != info.public_key;
        let was_offline = !is_new && !old_online;
        let previous_virtual_ip = if !is_new && !old_virtual_ip.is_empty() {
            Some(old_virtual_ip.clone())
        } else {
            None
        };

        if virtual_ip_changed
            && ip_map.get(&old_virtual_ip).map(String::as_str) == Some(info.node_id.as_str())
        {
            ip_map.remove(&old_virtual_ip);
        }
        conn.virtual_ip = info.virtual_ip.clone();
        conn.device_name = info.device_name.clone();
        conn.app_version = info.app_version.clone();
        if conn.public_key != info.public_key {
            conn.public_key = info.public_key.clone();
            conn.probe_mac_key = derive_probe_mac_key(&self.config, &info.public_key);
            if conn.probe_mac_key.is_none() {
                debug!(
                    "Peer {} has no usable Probe v2 MAC key; falling back to legacy UDP probes",
                    info.node_id
                );
            }
        }
        if public_key_changed {
            conn.reset_for_identity_change();
            cancel_heartbeat_after_lock = true;
            clear_hard_hard_after_lock = true;
        }
        // A same-key peer restart is still a new transport incarnation.  The
        // control plane deliberately keeps the connection entry while a peer
        // is offline, so `public_key_changed` cannot identify this boundary.
        // Clear every session-bound path artifact before publishing the new
        // online generation; otherwise a late task from the old incarnation
        // can leave an active/pending Probe-v2 binding behind.  Five such
        // pending bindings exhaust the bounded staging queue and make the
        // first offer of the replacement incarnation fail with `Busy`.
        // `reset_for_peer_session` retains the remote candidate high-water and
        // replay floor, which must continue fencing delayed old signals.
        if ((was_offline && info.online) || virtual_ip_changed) && !public_key_changed {
            conn.reset_for_peer_session();
            cancel_heartbeat_after_lock = true;
            clear_hard_hard_after_lock = true;
        }
        // The remote fresh-prediction space is bound to the peer's identity
        // (public key): a rejoin with a NEW key — including a PeerLeft
        // followed by `add_peer` with `is_new == true` — must not inherit the
        // old incarnation's high-water, or the new incarnation's predictions
        // would be judged stale against it forever. The identity ledger survives
        // `remove_peer`, so the comparison works even when the connection was
        // recreated.
        let (identity_changed, retained_candidate_incarnation, retained_candidate_generation) = {
            let mut identities = self
                .remote_identity_ledger
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let prior = identities.get(&info.node_id).cloned();
            // A missing ledger entry for an existing connection means only
            // that the bounded tombstone was evicted. The live connection is
            // still authoritative for both identity and incarnation.
            let changed = prior
                .as_ref()
                .is_some_and(|identity| identity.public_key != info.public_key)
                || (prior.is_none() && (is_new || public_key_changed));
            let retained = if changed {
                None
            } else {
                match (
                    conn.remote_candidate_incarnation_high_water,
                    prior
                        .as_ref()
                        .and_then(|identity| identity.candidate_incarnation_high_water),
                ) {
                    (Some(connection), Some(tombstone)) => Some(connection.max(tombstone)),
                    (connection, tombstone) => connection.or(tombstone),
                }
            };
            let retained_generation = if changed {
                0
            } else {
                conn.last_candidate_generation.max(
                    prior
                        .as_ref()
                        .map_or(0, |identity| identity.candidate_generation_replay_floor),
                )
            };
            identities.upsert_and_touch(
                &info.node_id,
                &info.public_key,
                retained,
                retained_generation,
            );
            (changed, retained, retained_generation)
        };
        conn.remote_candidate_incarnation_high_water = retained_candidate_incarnation;
        conn.last_candidate_generation = retained_candidate_generation;
        if identity_changed {
            clear_hard_hard_after_lock = true;
            // Clear the old identity's fresh high-water before membership for
            // the replacement is published below.  Unknown-peer responder work
            // wakes from that publication without taking `connections`; if the
            // reset were deferred until after publication, the new identity's
            // first (lower) prediction could be judged stale against the old
            // key's high-water and be lost permanently.
            self.reset_remote_fresh_generation_sync(
                &info.node_id,
                if public_key_changed {
                    "public_key_changed"
                } else {
                    "identity_key_changed_on_rejoin"
                },
            );
        }
        conn.nat_type = info.nat_type.clone();
        // An explicit offline transition revokes RelayPeerConfirmed: the peer
        // is not reachable, so the confirmed relay path must be re-established
        // by a fresh probe when it comes back online.  (Identity changes
        // already reset via `reset_for_identity_change`.)
        if conn.online && !info.online {
            revoke_relay_after_lock = true;
        }
        conn.online = info.online;
        conn.last_seen = info.last_seen;
        conn.remote_relay_rtt_ms = info.relay_rtt_ms;

        let signaled_endpoint = if info.endpoint.trim().is_empty() {
            None
        } else {
            match info.endpoint.parse::<SocketAddr>() {
                Ok(endpoint) => Some(endpoint),
                Err(error) => {
                    warn!(
                        "Ignoring invalid endpoint '{}' for peer {}: {error}",
                        info.endpoint, info.node_id
                    );
                    None
                }
            }
        };
        let endpoint_changed = !is_new && old_signaled_endpoint != signaled_endpoint;
        let last_seen_only = !is_new
            && old_last_seen != info.last_seen
            && !virtual_ip_changed
            && !public_key_changed
            && !endpoint_changed
            && old_device_name == info.device_name
            && old_app_version == info.app_version
            && old_nat_type == info.nat_type
            && old_online == info.online
            && old_remote_relay_rtt_ms == info.relay_rtt_ms;
        // PeerUpdated may carry a new host/private endpoint while an
        // encrypted-confirmed public pair is live. Keep the confirmed pair as
        // the active endpoint; the new value remains in signaled_endpoint and
        // can enter the candidate/probing set after Direct health fails.
        if (endpoint_changed
            && conn.endpoint == old_signaled_endpoint
            && !conn.direct_is_healthy_confirmed())
            || conn.endpoint.is_none()
        {
            conn.endpoint = signaled_endpoint;
        }
        conn.signaled_endpoint = signaled_endpoint;
        // The structured NAT label rides the existing peer metadata path. It
        // is parsed into an advisory capability snapshot, fenced by the
        // producer's profile generation; actual candidate/ACK evidence keeps
        // ownership of Direct-path promotion.
        let previous_remote_profile_generation = conn
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.generation);
        let previous_remote_profile_lifecycle = conn
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.registration_lifecycle);
        let previous_remote_profile_observation = conn
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.observation_sequence);
        let remote_profile_accepted =
            conn.update_remote_nat_profile(&info.nat_type, signaled_endpoint);
        let remote_profile_generation = conn
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.generation);
        let remote_profile_lifecycle = conn
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.registration_lifecycle);
        let remote_profile_observation = conn
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.observation_sequence);
        let mut recovery_reopen_reason_after_lock = None;
        let lifecycle_changed = previous_remote_profile_lifecycle != remote_profile_lifecycle;
        let generation_changed = previous_remote_profile_generation != remote_profile_generation;
        let observation_advanced = !lifecycle_changed
            && !generation_changed
            && match (
                previous_remote_profile_observation,
                remote_profile_observation,
            ) {
                (Some(previous), Some(current)) => current > previous,
                (None, Some(_)) => true,
                _ => false,
            };
        if info.online
            && remote_profile_accepted
            && (lifecycle_changed || generation_changed || observation_advanced)
        {
            // Capability or registration replacement invalidates an active
            // fresh-mapping rendezvous. A same-capability `o=` advance is
            // intentionally lighter: it renews evidence and grants the
            // bounded recovery epoch another attempt without tearing down a
            // healthy Direct path or rekeying an encrypted session.
            if lifecycle_changed || generation_changed {
                clear_hard_hard_after_lock = true;
            }
            if previous_remote_profile_generation.is_some()
                || remote_profile_generation.is_some()
                || previous_remote_profile_lifecycle.is_some()
                || remote_profile_lifecycle.is_some()
                || previous_remote_profile_observation.is_some()
                || remote_profile_observation.is_some()
            {
                recovery_reopen_reason_after_lock = Some(if lifecycle_changed {
                    "remote_nat_registration_lifecycle_advanced"
                } else if generation_changed {
                    "remote_nat_profile_generation_advanced"
                } else {
                    "remote_nat_profile_observation_advanced"
                });
            }
        }
        if let Some(addr) = signaled_endpoint {
            conn.ensure_candidate_pair(addr, generation);
        }
        if !info.online {
            clear_hard_hard_after_lock = true;
            conn.relay_server = None;
            cancel_heartbeat_after_lock = true;
            conn.probe_session_id = None;
            conn.probe_ephemeral_shared = None;
            conn.probe_binding_token = None;
            conn.pending_probe_bindings.clear();
            conn.previous_probe_binding = None;
        }

        // A relay 404 is authoritative evidence that the peer's registration
        // is absent on the relay.  Only evidence that the peer is a NEW
        // instance re-opens the registration-grace window: a brand-new node
        // ID (fresh registration) or a changed public key (identity rotation
        // / reinstall).  Endpoint heartbeats, `last_seen` growth, ordinary
        // NAT endpoint churn and online transitions are all consistent with
        // the SAME stale incarnation still missing its relay registration, so
        // they must NOT clear the grace window (field evidence: old v0.1.108 /
        // v0.1.110 nodes kept restarting 404 grace and quarantine churn on
        // every control-plane heartbeat while their relay registration was
        // permanently absent).
        let clear_relay_not_found_grace_after_lock = info.online && (is_new || public_key_changed);

        // Authoritative recovery re-open for a quarantined peer is limited to
        // identity/incarnation change (public-key rotation) and new
        // registrations.  Endpoint churn on a stale incarnation is NOT
        // authoritative: the NAT endpoint moves every heartbeat while the
        // relay registration stays absent, and unquarantining on it would
        // restart the whole punch / relay-404 / re-quarantine storm on every
        // poll.  Authenticated inbound evidence (a live encrypted punch from
        // the peer) is handled by `learn_authenticated_endpoint`, and a
        // PeerLeft removes the quarantine in `remove_peer`.  The re-open is
        // deferred until the connection map guard is released to avoid
        // re-locking it inside `unquarantine_peer`.
        if identity_changed && info.online && self.peer_quarantined_sync(&info.node_id) {
            unquarantine_after_lock = Some("identity/incarnation change");
        }

        ip_map.insert(info.virtual_ip.clone(), info.node_id.clone());
        // Publish the complete routing index after the authoritative map has
        // been updated. Dataplane lookups consume this immutable snapshot and
        // therefore never wait behind this control-plane writer.
        self.ip_to_node_snapshot
            .send_replace(Arc::new(ip_map.clone()));
        // Publish membership only after the connection is fully initialized.
        // Readers of the no-await mirror may then safely dispatch candidate
        // work without mistaking an in-progress PeerJoined for a ready peer.
        // Rotate the process-local generation only at a structural, identity,
        // or online lifecycle boundary; metadata and endpoint churn retain it.
        let rotate_peer_session =
            is_new || public_key_changed || virtual_ip_changed || old_online != info.online;
        let published_generation = self
            .peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .publish(&info.node_id, info.online, rotate_peer_session);
        if let Some(peer_session_generation) = published_generation {
            let epoch = PathEpoch::new(
                generation,
                peer_session_generation,
                conn.remote_candidate_epoch(),
            );
            let event = if info.online {
                PathEvent::PeerOnline { epoch }
            } else {
                PathEvent::PeerLeft { epoch }
            };
            conn.commit_path_transition(event, |_| {});
        } else {
            warn!(
                "Peer lifecycle generation exhausted while publishing {}; authentication disabled",
                info.node_id
            );
        }
        lock_trace.emit_peer_update_phase("peer_update_commit_complete", "state_committed");
        #[cfg(test)]
        pause_after_peer_membership_publish_for_test(&info.node_id).await;
        drop(conns);
        drop(ip_map);
        drop(epoch_guard);
        lock_trace.released(PeerUpdateLockResource::IpToNodeWrite);
        lock_trace.released(PeerUpdateLockResource::ConnectionsWrite);
        lock_trace.released(PeerUpdateLockResource::NetworkEpochGate);
        if clear_hard_hard_after_lock {
            self.clear_hard_hard_sessions(Some(&info.node_id)).await;
        }
        if revoke_relay_after_lock {
            self.revoke_relay_peer_confirmation(&info.node_id).await;
        }
        if cancel_heartbeat_after_lock {
            self.cancel_relay_backoff_heartbeat(&info.node_id);
        }
        if clear_relay_not_found_grace_after_lock {
            self.clear_relay_not_found_grace(&info.node_id).await;
        }
        if let Some(reason) = unquarantine_after_lock {
            self.unquarantine_peer(&info.node_id, reason).await;
        }
        if let Some(reason) = recovery_reopen_reason_after_lock {
            self.recovery_reopen_on_evidence(&info.node_id, reason)
                .await;
        }
        lock_trace.emit_peer_update_phase(
            "peer_update_postcommit_cleanup_completed",
            "postcommit_cleanup_completed",
        );
        PeerUpdate {
            is_new,
            virtual_ip_changed,
            endpoint_changed,
            public_key_changed,
            last_seen_only,
            previous_virtual_ip,
            was_offline,
        }
    }
}

impl PeerManager {
    /// Remove a peer.
    ///
    /// A plain PeerLeft must NOT clear the remote fresh high-water: a late
    /// signal from the old incarnation must stay rejected after the peer
    /// rejoins, and the new incarnation's strictly-monotonic counter
    /// supersedes the old one anyway.  Only a public-key / identity change
    /// resets the fresh space.
    pub async fn remove_peer(&self, node_id: &str) {
        let removed_relay_expectation = {
            let dplpmtud_runtime = self.dplpmtud_runtime.read().await.clone();
            let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
            // PeerLeft is an authoritative quarantine lifecycle boundary.
            // Remove both the backoff metadata and the no-await dataplane
            // mirror under the same epoch used for membership removal, before
            // any later re-add can publish the replacement lifecycle.
            self.quarantined_peers.lock().await.remove(node_id);
            self.quarantine_deadline_mirror
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(node_id);
            if let Some(conn) = conns.get(node_id) {
                self.remote_identity_ledger
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .upsert_and_touch(
                        node_id,
                        &conn.public_key,
                        conn.remote_candidate_incarnation_high_water,
                        conn.last_candidate_generation,
                    );
            }
            let peer_session_generation = self
                .peer_membership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .generation(node_id);
            if let (Some(conn), Some(peer_session_generation)) =
                (conns.get_mut(node_id), peer_session_generation)
            {
                let epoch = PathEpoch::new(
                    self.current_network_generation_sync(),
                    peer_session_generation,
                    conn.remote_candidate_epoch(),
                );
                conn.commit_path_transition(PathEvent::PeerLeft { epoch }, |_| {});
            }
            // This is the lifecycle linearization point: once the mirror is
            // cleared, no new UDP adoption or control candidate work may treat
            // the old connection as present, even though physical map cleanup
            // follows immediately under the same writer.
            self.peer_membership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(node_id);
            if let Some(removed) = conns.remove(node_id) {
                let mut ip_map = self.ip_to_node.write().await;
                if ip_map
                    .get(&removed.virtual_ip)
                    .is_some_and(|owner| owner == node_id)
                {
                    ip_map.remove(&removed.virtual_ip);
                    self.ip_to_node_snapshot
                        .send_replace(Arc::new(ip_map.clone()));
                }
            }
            self.committed_business_paths
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(node_id);
            if let Some(runtime) = dplpmtud_runtime {
                runtime.cancel_peer(node_id, "peer_left", tokio::time::Instant::now());
            }
            // PeerLeft is a terminal boundary for the current peer session.
            // Cancel the forced-relay token while the same epoch gate covers
            // removal, so an old ACK cannot race a later re-add of this node
            // ID and confirm the replacement connection.
            let removed_relay_expectation = self
                .relay_probe_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(node_id)
                .is_some();
            removed_relay_expectation
        };
        if removed_relay_expectation {
            self.emit_timeline(
                "relay_probe_expectation_cancelled",
                Some("relay"),
                Some("peer_removed"),
                Some(format!("peer={node_id}")),
            );
        }
        self.cancel_relay_backoff_heartbeat(node_id);
        self.clear_relay_not_found_grace(node_id).await;
        self.direct_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(node_id);
        self.recovery_epoch_end(node_id, "peer_removed").await;
        self.clear_fresh_mapping(node_id, "peer_removed").await;
        self.clear_hard_hard_sessions(Some(node_id)).await;
    }
}

impl PeerManager {
    /// Get a peer connection by node ID.
    pub async fn get_connection(&self, node_id: &str) -> Option<PeerConnection> {
        #[cfg(test)]
        self.notify_candidate_postprocess_lock_wait_for_test();
        self.connections.read().await.get(node_id).cloned()
    }

    /// Look up the node ID for a virtual IP.
    pub async fn resolve_virtual_ip(&self, virtual_ip: &str) -> Option<String> {
        self.ip_to_node_snapshot.borrow().get(virtual_ip).cloned()
    }
}
