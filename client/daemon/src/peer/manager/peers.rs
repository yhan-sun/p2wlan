fn normalize_probe_session_id(session_id: Option<String>) -> Option<String> {
    session_id.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn prune_probe_session_bindings(conn: &mut PeerConnection, now: Instant) {
    conn.pending_probe_bindings
        .retain(|_, pending| pending.expires_at > now);
    if conn
        .previous_probe_binding
        .as_ref()
        .is_some_and(|previous| previous.expires_at <= now)
    {
        conn.previous_probe_binding = None;
    }
}

fn install_active_probe_binding(
    conn: &mut PeerConnection,
    binding: ProbeSessionBinding,
    retain_previous: bool,
) -> bool {
    let previous = active_probe_binding(conn);
    let replaced = previous != binding;
    if retain_previous && replaced {
        conn.previous_probe_binding = Some(RetainedProbeSessionBinding {
            binding: previous,
            expires_at: Instant::now() + PROBE_SESSION_BINDING_OVERLAP,
        });
    } else if !retain_previous {
        conn.previous_probe_binding = None;
    }
    conn.probe_binding_token = binding.token.clone();
    conn.probe_session_id = binding.session_id.clone();
    conn.probe_ephemeral_shared = binding.ephemeral_shared;
    conn.pending_probe_bindings.clear();
    replaced
}

fn push_unique_probe_key(
    candidates: &mut Vec<ProbeKeyCandidate>,
    key: ProbeMacKey,
    role: ProbeKeyRole,
    session_id: Option<String>,
    session_generation: PeerSessionGeneration,
) {
    if !candidates.iter().any(|candidate| candidate.key == key) {
        candidates.push(ProbeKeyCandidate {
            key,
            role,
            session_generation,
            session_id,
        });
    }
}

fn push_probe_binding_compatibility_keys(
    candidates: &mut Vec<ProbeKeyCandidate>,
    base_key: ProbeMacKey,
    binding: &ProbeSessionBinding,
    session_generation: PeerSessionGeneration,
) {
    if let Some(session_id) = binding.session_id.as_deref() {
        push_unique_probe_key(
            candidates,
            derive_session_probe_mac_key(&base_key, session_id),
            ProbeKeyRole::Compatibility,
            binding.session_id.clone(),
            session_generation,
        );
    }
}

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
fn peer_membership_publish_test_gate_slot(
) -> &'static PeerMembershipPublishTestGateSlot {
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
    /// Mirror a connection's accepted remote daemon incarnation into the
    /// bounded identity ledger. Callers already own `network_epoch_gate` and
    /// the connection writer, so `add_peer`/`remove_peer` use the same
    /// `epoch -> connections -> identity-ledger` order.
    fn record_remote_candidate_incarnation_high_water(
        &self,
        node_id: &str,
        public_key: &str,
        incarnation: u64,
    ) {
        self.remote_identity_ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_candidate_incarnation(node_id, public_key, incarnation);
    }

    /// Raise the encoded candidate replay floor in the bounded identity
    /// ledger. Candidate apply records the accepted generation itself; ingress
    /// preflight records its strict predecessor so a same-key PeerLeft/rejoin
    /// before apply cannot admit a lower counter. Legacy generations are
    /// ignored by the ledger implementation.
    fn record_remote_candidate_generation_replay_floor(
        &self,
        node_id: &str,
        public_key: &str,
        generation: u64,
    ) {
        self.remote_identity_ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_candidate_generation_replay_floor(node_id, public_key, generation);
    }

    /// Publish the strict replay floor for one valid encoded generation, then
    /// claim a strictly newer remote daemon incarnation when necessary.
    ///
    /// The replay floor is published for first-incarnation and same-incarnation
    /// signals too: candidate apply happens after this helper returns, so a
    /// PeerLeft/rejoin in that gap must not admit a lower counter. A new
    /// incarnation claim remains the high-water linearization point before
    /// slow WireGuard/UDP cleanup.
    pub(crate) async fn claim_remote_candidate_incarnation_for_identity(
        &self,
        node_id: &str,
        candidate_generation: u64,
        sender_public_key: Option<&str>,
    ) -> RemoteCandidateIncarnationClaim {
        // Only an absent fingerprint is legacy-compatible. An explicitly
        // present but empty fingerprint is malformed identity evidence and
        // must fail closed like every other non-matching `Some` value.
        let sender_public_key = sender_public_key.map(str::trim);
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let mut connections = self.connections.write().await;
        let Some(conn) = connections.get_mut(node_id) else {
            return if sender_public_key.is_some() {
                RemoteCandidateIncarnationClaim::IdentityMismatch
            } else {
                RemoteCandidateIncarnationClaim::NoReset
            };
        };
        if sender_public_key
            .is_some_and(|public_key| public_key.is_empty() || conn.public_key.trim() != public_key)
        {
            return RemoteCandidateIncarnationClaim::IdentityMismatch;
        }
        let Some(new_incarnation) =
            crate::control::candidate_generation_incarnation(candidate_generation)
        else {
            return RemoteCandidateIncarnationClaim::NoReset;
        };
        let Some(claim_floor) =
            crate::control::candidate_generation_predecessor_floor(candidate_generation)
        else {
            return RemoteCandidateIncarnationClaim::NoReset;
        };
        conn.last_candidate_generation = conn.last_candidate_generation.max(claim_floor);
        self.record_remote_candidate_generation_replay_floor(
            node_id,
            &conn.public_key,
            claim_floor,
        );
        let Some(old_incarnation) = conn.remote_candidate_incarnation_high_water else {
            conn.remote_candidate_incarnation_high_water = Some(new_incarnation);
            self.record_remote_candidate_incarnation_high_water(
                node_id,
                &conn.public_key,
                new_incarnation,
            );
            return RemoteCandidateIncarnationClaim::NoReset;
        };
        if new_incarnation <= old_incarnation {
            return RemoteCandidateIncarnationClaim::NoReset;
        }
        conn.remote_candidate_incarnation_high_water = Some(new_incarnation);
        // The predecessor was published above before this claim. Mirror the
        // new incarnation itself before slow transport cleanup as the second
        // half of the replay fence.
        self.record_remote_candidate_incarnation_high_water(
            node_id,
            &conn.public_key,
            new_incarnation,
        );
        RemoteCandidateIncarnationClaim::Reset {
            old_incarnation,
            new_incarnation,
        }
    }

    /// Compatibility wrapper for internal tests that exercise only incarnation
    /// ordering and do not model the server-bound sender identity.
    #[cfg(test)]
    pub(crate) async fn claim_remote_candidate_incarnation_if_newer(
        &self,
        node_id: &str,
        candidate_generation: u64,
    ) -> Option<(u64, u64)> {
        match self
            .claim_remote_candidate_incarnation_for_identity(node_id, candidate_generation, None)
            .await
        {
            RemoteCandidateIncarnationClaim::Reset {
                old_incarnation,
                new_incarnation,
            } => Some((old_incarnation, new_incarnation)),
            RemoteCandidateIncarnationClaim::IdentityMismatch
            | RemoteCandidateIncarnationClaim::NoReset => None,
        }
    }

    /// Finish a previously claimed remote restart after old WireGuard and UDP
    /// work has been stopped. The high-water equality check prevents an older
    /// cleanup owner from resetting state claimed by a later incarnation.
    pub(crate) async fn finish_claimed_remote_incarnation_reset(
        &self,
        node_id: &str,
        old_incarnation: u64,
        claimed_incarnation: u64,
        reason: &str,
    ) -> bool {
        let had_relay_confirmation = {
            let epoch_gate = self.network_epoch_gate();
            let _epoch_guard = epoch_gate.lock().await;
            let mut connections = self.connections.write().await;
            let Some(conn) = connections.get_mut(node_id) else {
                return false;
            };
            if conn.remote_candidate_incarnation_high_water != Some(claimed_incarnation) {
                return false;
            }
            let had_relay_confirmation = conn.relay_confirmed_at.is_some();
            conn.reset_for_peer_session();
            let published = self
                .peer_membership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .publish(node_id, conn.online, true);
            if !published {
                warn!(
                    "Peer lifecycle generation exhausted while resetting remote incarnation for {node_id}; authentication disabled"
                );
            }
            if had_relay_confirmation {
                conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                self.bump_relay_confirm_seq(node_id);
            }
            had_relay_confirmation
        };
        self.clear_hard_hard_sessions(Some(node_id)).await;
        self.emit_timeline(
            "peer_restart_detected",
            None,
            Some(reason),
            Some(format!(
                "peer={node_id} reason={reason} old_incarnation={old_incarnation} new_incarnation={claimed_incarnation} relay_confirmation_cleared={had_relay_confirmation}"
            )),
        );
        true
    }

    /// Convenience wrapper for tests and callers that do not need to compose
    /// transport cleanup between the claim and connection reset.
    #[cfg(test)]
    pub(crate) async fn reset_peer_session_if_remote_incarnation_changed(
        &self,
        node_id: &str,
        candidate_generation: u64,
        reason: &str,
    ) -> bool {
        let Some((old_incarnation, claimed_incarnation)) = self
            .claim_remote_candidate_incarnation_if_newer(node_id, candidate_generation)
            .await
        else {
            return false;
        };
        self.finish_claimed_remote_incarnation_reset(
            node_id,
            old_incarnation,
            claimed_incarnation,
            reason,
        )
        .await
    }

    /// Add or update a peer from control plane info.
    pub async fn add_peer(&self, info: &PeerInfo) -> PeerUpdate {
        // Control-plane incarnation updates are another writer of the same
        // relay/session state that network handover invalidates. Serialize
        // the generation snapshot and the connection mutation as one epoch
        // transaction; otherwise a public-key/session reset could be
        // published immediately before an old ACK commits.
        let epoch_gate = self.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
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
        let mut conns = self.connections.write().await;
        let mut ip_map = self.ip_to_node.write().await;

        let is_new = !conns.contains_key(&info.node_id);

        let conn = conns
            .entry(info.node_id.clone())
            .or_insert_with(|| PeerConnection::new(&info.node_id, &info.virtual_ip));
        // Keep the synchronous Direct-set mirror attached to every connection
        // so its `transition` keeps the UDP eviction's nonevictable set fresh.
        conn.attach_direct_cache(self.direct_peers.clone());
        conn.attach_direct_pair_cache(self.direct_commit_pair_mirror.clone());

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
        let remote_profile_accepted =
            conn.update_remote_nat_profile(&info.nat_type, signaled_endpoint);
        let remote_profile_generation = conn
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.generation);
        if remote_profile_accepted
            && previous_remote_profile_generation != remote_profile_generation
        {
            clear_hard_hard_after_lock = true;
        }
        if let Some(addr) = signaled_endpoint {
            conn.ensure_candidate_pair(addr, generation);
        }
        if !info.online {
            clear_hard_hard_after_lock = true;
            conn.transition(ConnectionState::Closed);
            conn.relay_server = None;
            cancel_heartbeat_after_lock = true;
            conn.probe_session_id = None;
            conn.probe_ephemeral_shared = None;
            conn.probe_binding_token = None;
            conn.pending_probe_bindings.clear();
            conn.previous_probe_binding = None;
        } else if conn.state == ConnectionState::Closed {
            conn.transition(ConnectionState::Idle);
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
        // Publish membership only after the connection is fully initialized.
        // Readers of the no-await mirror may then safely dispatch candidate
        // work without mistaking an in-progress PeerJoined for a ready peer.
        // Rotate the process-local generation only at a structural, identity,
        // or online lifecycle boundary; metadata and endpoint churn retain it.
        let rotate_peer_session = is_new || public_key_changed || old_online != info.online;
        let published = self
            .peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .publish(&info.node_id, info.online, rotate_peer_session);
        if !published {
            warn!(
                "Peer lifecycle generation exhausted while publishing {}; authentication disabled",
                info.node_id
            );
        }
        #[cfg(test)]
        pause_after_peer_membership_publish_for_test(&info.node_id).await;
        drop(conns);
        drop(ip_map);
        drop(epoch_guard);
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
        PeerUpdate {
            is_new,
            virtual_ip_changed,
            endpoint_changed,
            public_key_changed,
            last_seen_only,
        }
    }

    /// Remove a peer.
    ///
    /// A plain PeerLeft must NOT clear the remote fresh high-water: a late
    /// signal from the old incarnation must stay rejected after the peer
    /// rejoins, and the new incarnation's strictly-monotonic counter
    /// supersedes the old one anyway.  Only a public-key / identity change
    /// resets the fresh space.
    pub async fn remove_peer(&self, node_id: &str) {
        let (removed_virtual_ip, removed_relay_expectation) = {
            let epoch_gate = self.network_epoch_gate();
            let _epoch_guard = epoch_gate.lock().await;
            // PeerLeft is an authoritative quarantine lifecycle boundary.
            // Remove both the backoff metadata and the no-await dataplane
            // mirror under the same epoch used for membership removal, before
            // any later re-add can publish the replacement lifecycle.
            self.quarantined_peers.lock().await.remove(node_id);
            self.quarantine_deadline_mirror
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(node_id);
            let mut conns = self.connections.write().await;
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
            // This is the lifecycle linearization point: once the mirror is
            // cleared, no new UDP adoption or control candidate work may treat
            // the old connection as present, even though physical map cleanup
            // follows immediately under the same writer.
            self.peer_membership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(node_id);
            let removed_virtual_ip = conns.remove(node_id).map(|conn| conn.virtual_ip);
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
            (removed_virtual_ip, removed_relay_expectation)
        };
        if removed_relay_expectation {
            self.emit_timeline(
                "relay_probe_expectation_cancelled",
                Some("relay"),
                Some("peer_removed"),
                Some(format!("peer={node_id}")),
            );
        }
        if let Some(virtual_ip) = removed_virtual_ip {
            let mut ip_map = self.ip_to_node.write().await;
            ip_map.remove(&virtual_ip);
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

    /// Get a peer connection by node ID.
    pub async fn get_connection(&self, node_id: &str) -> Option<PeerConnection> {
        self.connections.read().await.get(node_id).cloned()
    }

    /// Look up the node ID for a virtual IP.
    pub async fn resolve_virtual_ip(&self, virtual_ip: &str) -> Option<String> {
        self.ip_to_node.read().await.get(virtual_ip).cloned()
    }

    /// Update a peer's connection state.
    pub async fn update_state(&self, node_id: &str, state: ConnectionState) {
        let updated = {
            let mut conns = self.connections.write().await;
            if let Some(conn) = conns.get_mut(node_id) {
                conn.transition(state);
                true
            } else {
                false
            }
        };
        if updated
            && !matches!(
                state,
                ConnectionState::Relay | ConnectionState::FallbackToRelay
            )
        {
            self.cancel_relay_backoff_heartbeat(node_id);
        }
    }

    /// Transition connection state only for the exact online peer lifecycle
    /// that admitted delayed handshake work. The epoch gate makes the
    /// generation check and connection mutation one commit, so a same-node
    /// leave/rejoin cannot receive the old task's state transition.
    pub(crate) async fn update_state_if_peer_session_current(
        &self,
        node_id: &str,
        expected: PeerSessionGeneration,
        state: ConnectionState,
    ) -> bool {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        if !self.peer_session_is_current_sync(node_id, expected) {
            return false;
        }
        let updated = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            if !conn.online || conn.state == ConnectionState::Closed {
                return false;
            }
            conn.transition(state);
            true
        };
        if updated
            && !matches!(
                state,
                ConnectionState::Relay | ConnectionState::FallbackToRelay
            )
        {
            self.cancel_relay_backoff_heartbeat(node_id);
        }
        updated
    }

    /// Atomically re-check the state observed before an asynchronous punch
    /// setup and, if it is still current, enter HolePunching.  The caller
    /// must not make this decision from a cloned `PeerConnection`: Direct
    /// promotion may have committed while candidate refresh or HTTP work was
    /// in flight.
    pub(crate) async fn begin_hole_punch_if_current(
        &self,
        node_id: &str,
        observed_generation: u64,
        observed_commit_seq: Option<u64>,
    ) -> bool {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        if self.current_network_generation_sync() != observed_generation
            || self.direct_commit_seq_sync(node_id) != observed_commit_seq
        {
            return false;
        }
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        if conn.state == ConnectionState::Direct && conn.direct_is_healthy_confirmed() {
            return false;
        }
        if !matches!(conn.state, ConnectionState::Direct | ConnectionState::Relay) {
            conn.transition(ConnectionState::HolePunching);
        }
        true
    }

    /// Record a direct traversal timeline event for diagnostics.
    pub async fn record_direct_event(
        &self,
        node_id: &str,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        // Ordinary diagnostics must never become a back-pressure point for the
        // control event loop. A direct probe, candidate handover or relay
        // renewal may briefly own the connection map while it commits state;
        // the typed timeline event below remains authoritative when that map
        // is contended. Hard↔Hard terminal markers remain durable, while the
        // pre-send sweep marker is intentionally best-effort so it cannot
        // delay the first UDP datagram.
        let generation = self.current_network_generation_sync();
        let stage = stage.into();
        let detail = detail.into();
        if Self::direct_event_requires_durable_ring(&stage) {
            let mut connections = self.connections.write().await;
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event(
                    generation,
                    stage.clone(),
                    endpoint,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        } else if let Ok(mut connections) = self.connections.try_write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event(
                    generation,
                    stage.clone(),
                    endpoint,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        }
        self.emit_direct_traversal_debug(
            node_id,
            generation,
            &stage,
            endpoint,
            None,
            candidate_count,
            sent_probes,
            &detail,
        );
    }

    /// Generation-stable direct-event recorder with the actual UDP socket
    /// index when receive-side code can identify it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_event_for_generation_with_socket(
        &self,
        node_id: &str,
        generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let stage = stage.into();
        let detail = detail.into();
        if Self::direct_event_requires_durable_ring(&stage) {
            let mut connections = self.connections.write().await;
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event_with_socket(
                    generation,
                    stage.clone(),
                    endpoint,
                    socket_index,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        } else if let Ok(mut connections) = self.connections.try_write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event_with_socket(
                    generation,
                    stage.clone(),
                    endpoint,
                    socket_index,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        }
        self.emit_direct_traversal_debug(
            node_id,
            generation,
            &stage,
            endpoint,
            socket_index,
            candidate_count,
            sent_probes,
            &detail,
        );
    }

    /// Hard↔Hard winner and terminal markers are acceptance evidence, not
    /// best-effort trace noise. Wait for the connection writer for these
    /// bounded events so reciprocal validation cannot silently drop the
    /// selected-socket or final summary/failure evidence.
    /// `hard_hard_sweep_started` and
    /// `hard_hard_direct_validation_started` are deliberately excluded: both
    /// run on the punch-at/confirmation timing path and must not hold the
    /// first UDP send or confirmation grace behind the connection writer.
    fn direct_event_requires_durable_ring(stage: &str) -> bool {
        matches!(
            stage,
            "hard_hard_probe_summary"
                | "hard_hard_birthday_sweep_summary"
                | "hard_hard_sweep_completed"
                | "hard_hard_sweep_failed"
                | "hard_hard_failed"
                | "hard_hard_winner_selected"
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_direct_traversal_debug(
        &self,
        node_id: &str,
        generation: u64,
        stage: &str,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: &str,
    ) {
        let Some(event) = direct_traversal_timeline_event(stage) else {
            return;
        };
        let reason_code = detail
            .split_whitespace()
            .find_map(|part| part.strip_prefix("reason_code="))
            .filter(|value| !value.is_empty())
            .or_else(|| direct_traversal_default_reason(stage));
        self.emit_timeline_debug(
            event,
            Some("direct"),
            reason_code,
            Some(format_direct_traversal_timeline_detail(
                node_id,
                generation,
                stage,
                endpoint,
                socket_index,
                candidate_count,
                sent_probes,
                detail,
            )),
        );
    }

    /// Record a lifecycle event for one owned encrypted direct-validation
    /// worker.  The worker's lease supplies `generation` and
    /// `validation_session_id`; do not substitute the manager's current
    /// generation here because this method is also used to explain a worker
    /// that was cancelled by a generation advance.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event(
        &self,
        node_id: &str,
        generation: u64,
        validation_session_id: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.record_direct_validation_event_with_socket(
            node_id,
            generation,
            validation_session_id,
            stage,
            endpoint,
            None,
            candidate_count,
            sent_probes,
            detail,
        )
        .await;
    }

    /// Generation- and owner-stable validation lifecycle recorder with the
    /// actual UDP socket index where it is available.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event_with_socket(
        &self,
        node_id: &str,
        generation: u64,
        validation_session_id: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.record_direct_validation_event_with_metadata(
            node_id,
            generation,
            DirectValidationEventMetadata {
                local_validation_session_id: Some(validation_session_id),
                ..DirectValidationEventMetadata::default()
            },
            stage,
            endpoint,
            socket_index,
            candidate_count,
            sent_probes,
            detail,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event_with_metadata(
        &self,
        node_id: &str,
        generation: u64,
        metadata: DirectValidationEventMetadata,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let stage = stage.into();
        let detail = detail.into();
        if let Ok(mut connections) = self.connections.try_write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_validation_event_with_metadata(
                    generation,
                    metadata,
                    stage.clone(),
                    endpoint,
                    socket_index,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        }

        // The `/status` direct-event ring already has the full typed record,
        // but it is only collected after a round.  Mirror the lifecycle into
        // the process timeline at DEBUG level so a live failure can be
        // diagnosed from one log stream with the same corr_id/t_ms as relay,
        // WireGuard and generation events.  Do not copy validation owner
        // tokens from the legacy detail strings into this log line.
        if let Some(event) = direct_validation_timeline_event(&stage) {
            let reason_code = detail
                .split_whitespace()
                .find_map(|part| part.strip_prefix("reason_code="))
                .filter(|value| !value.is_empty())
                .or_else(|| direct_validation_default_reason(&stage));
            let timeline_detail = format_direct_validation_timeline_detail(
                node_id,
                generation,
                &stage,
                endpoint,
                socket_index,
                candidate_count,
                sent_probes,
                metadata,
                &detail,
            );
            self.emit_timeline_debug(event, Some("direct"), reason_code, Some(timeline_detail));
        }
    }

    /// Record a direct traversal event with structured probe coverage counters.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_direct_event_with_probe_coverage(
        &self,
        node_id: &str,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
        socket0_count: u32,
        alt_socket_count: u32,
        unique_target_ports: u32,
        repeated_target_ports: u32,
    ) {
        let generation = self.current_network_generation_sync();
        if let Ok(mut connections) = self.connections.try_write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event_with_probe_coverage(
                    generation,
                    stage,
                    endpoint,
                    candidate_count,
                    sent_probes,
                    detail,
                    socket0_count,
                    alt_socket_count,
                    unique_target_ports,
                    repeated_target_ports,
                );
            }
        }
    }

    /// Set the explicit control-plane session ID used to bind Probe v2 MAC keys.
    pub async fn set_probe_session_id(&self, node_id: &str, session_id: Option<String>) -> bool {
        let normalized = normalize_probe_session_id(session_id);
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.pending_probe_bindings.clear();
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: None,
                session_id: normalized,
                ephemeral_shared: None,
            },
            false,
        );
        true
    }

    /// Set the explicit traversal session and optional ephemeral X25519 shared secret.
    pub async fn set_probe_session_binding(
        &self,
        node_id: &str,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
    ) -> bool {
        let normalized = normalize_probe_session_id(session_id);
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.pending_probe_bindings.clear();
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: None,
                session_id: normalized,
                ephemeral_shared,
            },
            false,
        );
        true
    }

    /// Stage a Probe-v2 replacement without changing the outbound key. A
    /// responder marks its staged key promotable by authenticated inbound
    /// traffic; an initiator waits for the matching answer and installs it
    /// explicitly.
    pub(crate) async fn stage_probe_session_binding(
        &self,
        node_id: &str,
        token: String,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
        promote_on_match: bool,
    ) -> ProbeBindingStage {
        let token = token.trim().to_string();
        if token.is_empty() {
            return ProbeBindingStage::StaleDuplicate;
        }
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return ProbeBindingStage::PeerMissing;
        };
        let now = Instant::now();
        prune_probe_session_bindings(conn, now);
        if conn.probe_binding_token.as_deref() == Some(token.as_str()) {
            return ProbeBindingStage::ReplayableDuplicate;
        }
        if let Some(pending) = conn.pending_probe_bindings.get_mut(&token) {
            // An exact cached answer replay gets a fresh delivery window.
            pending.expires_at = now + PENDING_PROBE_SESSION_BINDING_GRACE;
            return ProbeBindingStage::ReplayableDuplicate;
        }
        if conn
            .previous_probe_binding
            .as_ref()
            .and_then(|previous| previous.binding.token.as_deref())
            == Some(token.as_str())
        {
            return ProbeBindingStage::StaleDuplicate;
        }
        if conn.pending_probe_bindings.len() >= MAX_PENDING_PROBE_SESSION_BINDINGS_PER_PEER {
            return ProbeBindingStage::Busy;
        }
        conn.pending_probe_bindings.insert(
            token.clone(),
            PendingProbeSessionBinding {
                binding: ProbeSessionBinding {
                    token: Some(token),
                    session_id: normalize_probe_session_id(session_id),
                    ephemeral_shared,
                },
                expires_at: now + PENDING_PROBE_SESSION_BINDING_GRACE,
                promote_on_match,
            },
        );
        ProbeBindingStage::Staged
    }

    /// Extend a staged responder binding after the control-plane answer
    /// delivery attempt completes. This keeps signaling latency separate from
    /// the authenticated adoption window.
    pub(crate) async fn refresh_pending_probe_session_binding_grace(
        &self,
        node_id: &str,
        token: &str,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        let Some(pending) = conn.pending_probe_bindings.get_mut(token) else {
            return false;
        };
        pending.expires_at = Instant::now() + PENDING_PROBE_SESSION_BINDING_GRACE;
        true
    }

    /// Install an answer-confirmed Probe-v2 binding for outbound traffic while
    /// retaining the former inbound key during the overlap window.
    pub(crate) async fn install_probe_session_binding(
        &self,
        node_id: &str,
        token: String,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        prune_probe_session_bindings(conn, Instant::now());
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: Some(token),
                session_id: normalize_probe_session_id(session_id),
                ephemeral_shared,
            },
            true,
        );
        true
    }

    /// Roll back an unpublished Probe-v2 replacement. Returns false when the
    /// token was already promoted by authenticated traffic.
    pub(crate) async fn discard_pending_probe_session_binding(
        &self,
        node_id: &str,
        token: &str,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return true;
        };
        prune_probe_session_bindings(conn, Instant::now());
        if conn.probe_binding_token.as_deref() == Some(token) {
            return false;
        }
        conn.pending_probe_bindings.remove(token);
        true
    }

    /// Promote a responder's staged Probe-v2 binding after a packet validates
    /// under that exact key and token.
    pub(crate) async fn confirm_pending_probe_session_binding(
        &self,
        node_id: &str,
        token: &str,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        let should_promote = conn
            .pending_probe_bindings
            .get(token)
            .is_some_and(|pending| pending.promote_on_match);
        if !should_promote {
            return conn.probe_binding_token.as_deref() == Some(token);
        }
        let pending = conn
            .pending_probe_bindings
            .remove(token)
            .expect("pending Probe binding checked above");
        install_active_probe_binding(conn, pending.binding, true);
        true
    }

    /// Bridge a Probe-v2 adoption check with its matching WireGuard responder
    /// confirmation without holding the process-wide connection lock across
    /// an await.
    ///
    /// The UDP caller serializes this operation with the peer's adoption
    /// lifecycle lock.  The connection map is still re-checked after the
    /// transport await, so a peer removal, identity rotation, generation
    /// advance, or competing handshake commit cannot publish a stale Probe
    /// binding.  Keeping the map lock out of `confirm_transport` is important:
    /// WireGuard/session confirmation can wait on a slow transport, and a
    /// process-wide write lock there would block unrelated peer joins,
    /// control-signal consumption, and diagnostics snapshots.
    pub(crate) async fn confirm_probe_and_transport_transaction<F, Fut>(
        &self,
        node_id: &str,
        token: &str,
        confirm_transport: F,
    ) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let expected = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            prune_probe_session_bindings(conn, Instant::now());
            let should_promote = conn
                .pending_probe_bindings
                .get(token)
                .is_some_and(|pending| pending.promote_on_match);
            let already_active = conn.probe_binding_token.as_deref() == Some(token);
            if !should_promote && !already_active {
                return false;
            }
            (should_promote, already_active)
        };

        if !confirm_transport().await {
            return false;
        }

        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        prune_probe_session_bindings(conn, Instant::now());

        // A transport confirmation may complete after the peer was removed or
        // its binding was replaced.  In that case the transport result is
        // terminal for this transaction; never install the old counter/key
        // into the new connection generation.
        if conn.probe_binding_token.as_deref() == Some(token) {
            return true;
        }
        if !expected.0 || expected.1 {
            return false;
        }
        let Some(pending) = conn.pending_probe_bindings.remove(token) else {
            return false;
        };
        if !pending.promote_on_match {
            return false;
        }
        install_active_probe_binding(conn, pending.binding, true);
        true
    }

    /// Return the Probe v2 MAC key for a known peer, if both public keys are valid.
    ///
    /// New peers with an explicit signaling session ID receive a session-bound
    /// key; legacy peers without a session ID retain the static v2 skeleton key.
    pub async fn probe_key_for_peer(&self, node_id: &str) -> Option<ProbeMacKey> {
        self.probe_key_and_session_for_peer(node_id)
            .await
            .map(|(key, _)| key)
    }

    /// Return the active Probe v2 MAC key together with the session that
    /// derived it under one connection snapshot.  The session is carried by a
    /// pending outbound probe solely for diagnostics attribution; it is never
    /// trusted in place of MAC verification.
    pub(crate) async fn probe_key_and_session_for_peer(
        &self,
        node_id: &str,
    ) -> Option<(ProbeMacKey, Option<String>)> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|connection| {
                effective_probe_mac_key(connection)
                    .map(|key| (key, connection.probe_session_id.clone()))
            })
    }

    /// Snapshot the active Probe session for peer-scoped receive diagnostics.
    /// The value is not sent on the wire and cannot influence authentication.
    pub(crate) async fn probe_session_id_for_peer(&self, node_id: &str) -> Option<String> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|connection| connection.probe_session_id.clone())
    }

    /// Return role-tagged Probe-v2 keys for inbound authentication. Only an
    /// exact match on a promotable pending key can commit a responder rekey.
    pub(crate) async fn probe_key_candidates_for_peer(
        &self,
        node_id: &str,
    ) -> Vec<ProbeKeyCandidate> {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return Vec::new();
        };
        if !conn.online {
            return Vec::new();
        }
        let Some(session_generation) = self
            .peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_generation(node_id)
        else {
            return Vec::new();
        };
        prune_probe_session_bindings(conn, Instant::now());
        let Some(base_key) = conn.probe_mac_key else {
            return Vec::new();
        };

        let active = active_probe_binding(conn);
        let pending = conn.pending_probe_bindings.clone();
        let previous = conn.previous_probe_binding.clone();
        let mut candidates = Vec::new();
        push_unique_probe_key(
            &mut candidates,
            probe_mac_key_for_binding(base_key, &active),
            ProbeKeyRole::Active,
            active.session_id.clone(),
            session_generation,
        );
        for pending in pending.values() {
            let role = if pending.promote_on_match {
                ProbeKeyRole::Pending {
                    token: pending
                        .binding
                        .token
                        .clone()
                        .expect("staged Probe binding must have a token"),
                }
            } else {
                ProbeKeyRole::Compatibility
            };
            push_unique_probe_key(
                &mut candidates,
                probe_mac_key_for_binding(base_key, &pending.binding),
                role,
                pending.binding.session_id.clone(),
                session_generation,
            );
        }
        if let Some(previous) = previous.as_ref() {
            push_unique_probe_key(
                &mut candidates,
                probe_mac_key_for_binding(base_key, &previous.binding),
                ProbeKeyRole::Previous,
                previous.binding.session_id.clone(),
                session_generation,
            );
        }
        push_probe_binding_compatibility_keys(
            &mut candidates,
            base_key,
            &active,
            session_generation,
        );
        for pending in pending.values() {
            push_probe_binding_compatibility_keys(
                &mut candidates,
                base_key,
                &pending.binding,
                session_generation,
            );
        }
        if let Some(previous) = previous.as_ref() {
            push_probe_binding_compatibility_keys(
                &mut candidates,
                base_key,
                &previous.binding,
                session_generation,
            );
        }
        push_unique_probe_key(
            &mut candidates,
            base_key,
            ProbeKeyRole::Compatibility,
            None,
            session_generation,
        );
        candidates
    }

    /// Return Probe v2 MAC keys to try for inbound compatibility.
    ///
    /// The strongest key is first.  When a session ID is active, weaker
    /// session/static fallbacks are retained so upgraded peers can still receive
    /// probes from older clients or from signals relayed by older control servers.
    pub async fn probe_keys_for_peer(&self, node_id: &str) -> Vec<ProbeMacKey> {
        self.probe_key_candidates_for_peer(node_id)
            .await
            .into_iter()
            .map(|candidate| candidate.key)
            .collect()
    }
}

/// Stages that are useful in the live, correlation-id based timeline.  The
/// high-volume candidate/scatter events remain in the bounded `/status` ring;
/// these are the owned request/ACK lifecycle boundaries needed to explain a
/// Direct success, timeout, cancellation, or stale ACK from a daemon log.
fn direct_validation_timeline_event(stage: &str) -> Option<&'static str> {
    match stage {
        "direct_validation_queued" => Some("direct_validation_queued"),
        "direct_validation_dropped" => Some("direct_validation_dropped"),
        "direct_validation_started" => Some("direct_validation_started"),
        "direct_validation_waiting_for_session" => Some("direct_validation_waiting_for_session"),
        "direct_validation_session_ready" => Some("direct_validation_session_ready"),
        "direct_validation_request_prepared" => Some("direct_validation_request_prepared"),
        "direct_validation_request_sent" => Some("direct_validation_request_sent"),
        "direct_validation_request_received" => Some("direct_validation_request_received"),
        "direct_validation_request_dropped" => Some("direct_validation_request_dropped"),
        "direct_validation_ack_sent" => Some("direct_validation_ack_sent"),
        "direct_validation_ack_received" => Some("direct_validation_ack_received"),
        "direct_validation_ack_wait_timeout" => Some("direct_validation_ack_wait_timeout"),
        "direct_validation_ack_unmatched" => Some("direct_validation_ack_unmatched"),
        "direct_validation_ack_not_promoted" => Some("direct_validation_ack_not_promoted"),
        "direct_validation_ack_send_failed" => Some("direct_validation_ack_send_failed"),
        "direct_validation_emit_lock_timeout" => Some("direct_validation_emit_lock_timeout"),
        "direct_validation_timed_out" => Some("direct_validation_timed_out"),
        "direct_validation_failed" => Some("direct_validation_failed"),
        "direct_validation_cancelled" => Some("direct_validation_cancelled"),
        "direct_validation_completed" => Some("direct_validation_completed"),
        "direct_validation_promoted" => Some("direct_validation_promoted"),
        "direct_validation_suppressed" => Some("direct_validation_suppressed"),
        "direct_validation_slow_relay_retained" => Some("direct_validation_slow_relay_retained"),
        "direct_path_promoted" => Some("direct_path_promoted"),
        _ => None,
    }
}

fn direct_validation_default_reason(stage: &str) -> Option<&'static str> {
    match stage {
        "direct_validation_timed_out" => Some("direct_validation_timeout"),
        "direct_validation_failed" => Some("direct_validation_send_failed"),
        "direct_validation_cancelled" => Some("direct_validation_cancelled"),
        "direct_validation_ack_unmatched" => Some("direct_validation_ack_unmatched"),
        "direct_validation_ack_wait_timeout" => Some("direct_validation_ack_timeout"),
        "direct_validation_ack_send_failed" => Some("direct_validation_ack_send_failed"),
        "direct_validation_emit_lock_timeout" => Some("direct_validation_emit_lock_timeout"),
        "direct_validation_dropped" => Some("direct_validation_queue_dropped"),
        "direct_validation_request_dropped" => Some("direct_validation_request_dropped"),
        "direct_validation_ack_not_promoted" => Some("direct_validation_promotion_rejected"),
        "direct_validation_suppressed" => Some("direct_validation_suppressed"),
        _ => None,
    }
}

fn direct_traversal_timeline_event(stage: &str) -> Option<&'static str> {
    match stage {
        "direct_punch_started" => Some("direct_punch_started"),
        "direct_punch_completed" => Some("direct_punch_completed"),
        "direct_punch_failed" => Some("direct_punch_failed"),
        "direct_punch_cancelled" => Some("direct_punch_cancelled"),
        "direct_fast_probe_started" => Some("direct_fast_probe_started"),
        "direct_fast_probe_sent" => Some("direct_fast_probe_sent"),
        "direct_fast_probe_failed" => Some("direct_fast_probe_failed"),
        "direct_fast_probe_confirmed" => Some("direct_fast_probe_confirmed"),
        "direct_probe_ack_timeout" => Some("direct_probe_ack_timeout"),
        "direct_probe_budget_exhausted" => Some("direct_probe_budget_exhausted"),
        "direct_candidates_ready" => Some("direct_candidates_ready"),
        "candidate_pair_probe_succeeded" => Some("candidate_pair_probe_succeeded"),
        "retry_punch_started" => Some("retry_punch_started"),
        "retry_probes_sent" => Some("retry_probes_sent"),
        "retry_ack_timeout" => Some("retry_ack_timeout"),
        "retry_probe_succeeded" => Some("retry_probe_succeeded"),
        "retry_send_error" => Some("retry_send_error"),
        "direct_reclaim_punch_started" => Some("direct_reclaim_punch_started"),
        "direct_reclaim_probes_sent" => Some("direct_reclaim_probes_sent"),
        "direct_reclaim_ack_timeout" => Some("direct_reclaim_ack_timeout"),
        "direct_reclaim_probe_succeeded" => Some("direct_reclaim_probe_succeeded"),
        "direct_reclaim_send_error" => Some("direct_reclaim_send_error"),
        "fresh_mapping_generation_started" => Some("fresh_mapping_generation_started"),
        "fresh_mapping_generation_completed" => Some("fresh_mapping_generation_completed"),
        "fresh_mapping_generation_failed" => Some("fresh_mapping_generation_failed"),
        "fresh_mapping_prediction_signaled" => Some("fresh_mapping_prediction_signaled"),
        "direct_validation_observation_merged" => Some("direct_validation_observation_merged"),
        "direct_validation_suppressed" => Some("direct_validation_suppressed"),
        _ => None,
    }
}

fn direct_traversal_default_reason(stage: &str) -> Option<&'static str> {
    match stage {
        "direct_punch_failed"
        | "direct_fast_probe_failed"
        | "retry_send_error"
        | "direct_reclaim_send_error"
        | "fresh_mapping_generation_failed" => Some("direct_probe_failed"),
        "direct_punch_cancelled" => Some("direct_probe_cancelled"),
        "direct_probe_ack_timeout" | "retry_ack_timeout" | "direct_reclaim_ack_timeout" => {
            Some("direct_probe_ack_timeout")
        }
        "direct_probe_budget_exhausted" => Some("direct_probe_budget_exhausted"),
        "direct_validation_suppressed" => Some("direct_validation_suppressed"),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn format_direct_traversal_timeline_detail(
    peer_id: &str,
    generation: u64,
    stage: &str,
    endpoint: Option<SocketAddr>,
    socket_index: Option<usize>,
    candidate_count: Option<usize>,
    sent_probes: Option<u32>,
    detail: &str,
) -> String {
    format!(
        "peer_id={peer_id} generation={generation} stage={stage} endpoint={} socket_index={} candidate_count={} sent_probes={} detail={}",
        endpoint_text(endpoint),
        socket_index.map_or_else(|| "none".to_string(), |value| value.to_string()),
        candidate_count.map_or_else(|| "none".to_string(), |value| value.to_string()),
        sent_probes.map_or_else(|| "none".to_string(), |value| value.to_string()),
        sanitized_validation_detail(detail),
    )
}

fn endpoint_text(endpoint: Option<SocketAddr>) -> String {
    endpoint
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "none".to_string())
}

/// Keep the legacy human detail useful while ensuring local validation owner
/// handles (and anything accidentally labelled as a token) are not copied to
/// the live correlation log.  The typed `/status` record remains unchanged so
/// existing local diagnostics consumers keep working.
fn sanitized_validation_detail(detail: &str) -> String {
    detail
        .split_whitespace()
        .filter(|part| {
            let key = part.split_once('=').map(|(key, _)| key).unwrap_or_default();
            !matches!(
                key,
                "owner" | "owner_token" | "validation_session_id" | "token" | "ticket"
            )
        })
        .take(48)
        .collect::<Vec<_>>()
        .join(" ")
}

#[allow(clippy::too_many_arguments)]
fn format_direct_validation_timeline_detail(
    peer_id: &str,
    generation: u64,
    stage: &str,
    endpoint: Option<SocketAddr>,
    socket_index: Option<usize>,
    candidate_count: Option<usize>,
    sent_probes: Option<u32>,
    metadata: DirectValidationEventMetadata,
    detail: &str,
) -> String {
    format!(
        "peer_id={peer_id} generation={generation} stage={stage} endpoint={} socket_index={} candidate_count={} sent_probes={} request_id={} expected_endpoint={} observed_ack_endpoint={} selected_endpoint={} ack_endpoint_authenticated={} validation_rtt_ms={} detail={}",
        endpoint_text(endpoint),
        socket_index.map_or_else(|| "none".to_string(), |value| value.to_string()),
        candidate_count.map_or_else(|| "none".to_string(), |value| value.to_string()),
        sent_probes.map_or_else(|| "none".to_string(), |value| value.to_string()),
        metadata
            .request_id
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        endpoint_text(metadata.expected_endpoint),
        endpoint_text(metadata.observed_ack_endpoint),
        endpoint_text(metadata.selected_endpoint),
        metadata
            .ack_endpoint_authenticated
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        metadata
            .validation_rtt_ms
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        sanitized_validation_detail(detail),
    )
}

#[cfg(test)]
mod direct_validation_timeline_tests {
    use super::*;

    #[test]
    fn lifecycle_mapping_keeps_terminal_and_ack_boundaries() {
        assert_eq!(
            direct_validation_timeline_event("direct_validation_request_sent"),
            Some("direct_validation_request_sent")
        );
        assert_eq!(
            direct_validation_timeline_event("direct_validation_request_prepared"),
            Some("direct_validation_request_prepared")
        );
        assert_eq!(
            direct_validation_timeline_event("direct_validation_ack_unmatched"),
            Some("direct_validation_ack_unmatched")
        );
        assert_eq!(
            direct_validation_timeline_event("direct_validation_timed_out"),
            Some("direct_validation_timed_out")
        );
        assert_eq!(
            direct_validation_timeline_event("birthday_probe_sent"),
            None
        );
        assert_eq!(
            direct_validation_default_reason("direct_validation_timed_out"),
            Some("direct_validation_timeout")
        );
        assert_eq!(
            direct_traversal_timeline_event("direct_fast_probe_started"),
            Some("direct_fast_probe_started")
        );
        assert_eq!(
            direct_traversal_default_reason("retry_ack_timeout"),
            Some("direct_probe_ack_timeout")
        );
    }

    #[test]
    fn live_detail_redacts_local_owner_handles() {
        let detail = sanitized_validation_detail(
            "owner=123 owner_token=456 request_id=7 generation=9 reason_code=timeout",
        );
        assert!(!detail.contains("owner="));
        assert!(!detail.contains("owner_token="));
        assert!(detail.contains("request_id=7"));
        assert!(detail.contains("reason_code=timeout"));
    }
}
