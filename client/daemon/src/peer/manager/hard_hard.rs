// Hard↔Hard traversal admission and session fences.
//
// This file deliberately contains no socket sends and no path promotion. It
// only snapshots the authoritative planner inputs and keeps the short identity
// fence that lets the direct-runtime rendezvous reject an older response.

const MAX_HARD_HARD_SESSIONS: usize = 16;

#[derive(Debug, Clone, Copy)]
pub(crate) struct HardHardPlanSnapshot {
    pub(crate) local_network_generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) local_profile_generation: u64,
    pub(crate) remote_profile_generation: u64,
}

impl PeerManager {
    /// The local node id used to choose one deterministic Hard↔Hard initiator.
    pub(crate) fn local_node_id_for_traversal(&self) -> &str {
        &self.config.node.node_id
    }

    /// Return a point-in-time Hard↔Hard authorization snapshot.
    ///
    /// The pure planner remains the single strategy decision-maker.  This
    /// method reconstructs the same context from the live connection so the
    /// runtime cannot accidentally start Hard↔Hard for LAN, IPv6, learned,
    /// peer-reflexive, stale-profile, or already-Direct peers.
    pub(crate) async fn hard_hard_plan_for_peer(
        &self,
        peer_id: &str,
    ) -> Option<HardHardPlanSnapshot> {
        let local_generation = self.current_network_generation_sync();
        let local_profile_generation = self.current_local_profile_generation_sync();
        let local_profile = self.local_nat_profile.read().await.clone()?;
        let local = NatCapabilities::from_profile(&local_profile)
            .with_profile_generation(local_profile_generation);

        let conn = self.connections.read().await.get(peer_id)?.clone();
        if !conn.online || conn.state == ConnectionState::Direct {
            return None;
        }
        let remote_profile = conn.remote_nat_profile.as_ref()?;
        if !conn.remote_nat_profile_is_fresh() {
            return None;
        }
        let remote_profile_generation = remote_profile.generation?;
        let remote = remote_profile
            .capabilities
            .clone()
            .with_profile_generation(remote_profile_generation);

        let remote_candidates = conn
            .candidates
            .iter()
            .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
            .collect::<Vec<_>>();
        let on_link_lan = remote_candidates
            .iter()
            .any(|endpoint| conn.is_on_link_host_candidate(*endpoint));
        let global_ipv6_direct_available = local
            .stable_public_endpoint
            .as_deref()
            .and_then(|endpoint| endpoint.parse::<SocketAddr>().ok())
            .is_some_and(|endpoint| {
                endpoint.is_ipv6()
                    && remote_candidates.iter().any(|candidate| {
                        candidate.is_ipv6() && is_public_probe_endpoint(*candidate)
                    })
            });
        let peer_reflexive_evidence = conn.candidate_pairs.iter().any(|pair| {
            matches!(pair.source, CandidatePairSource::PeerReflexive)
                && matches!(
                    pair.state,
                    CandidatePairState::Succeeded | CandidatePairState::Selected
                )
        });
        let learned_endpoint_evidence = conn.candidate_pairs.iter().any(|pair| {
            matches!(pair.source, CandidatePairSource::Learned)
                && matches!(
                    pair.state,
                    CandidatePairState::Succeeded | CandidatePairState::Selected
                )
        });
        let remote_stable_endpoint_available = remote.is_stable_endpoint()
            || (!conn.remote_nat_profile.as_ref().is_some_and(|profile| {
                profile.capabilities.mapping_behavior != MappingBehavior::Unknown
            }) && conn.endpoint.is_some_and(is_public_probe_endpoint));
        let fresh_mapping_available = self
            .local_fresh_mappings
            .read()
            .await
            .get(peer_id)
            .is_some_and(|mapping| {
                mapping.network_generation == local_generation
                    && mapping.created_at.elapsed() <= FRESH_MAPPING_STATE_MAX_AGE
            });
        let context = TraversalContext {
            on_link_lan,
            global_ipv6_direct_available,
            peer_reflexive_evidence,
            learned_endpoint_evidence,
            local_stable_endpoint_available: local.is_stable_endpoint(),
            remote_stable_endpoint_available,
            fresh_mapping_available,
            remote_profile_fresh: true,
            relay_available: self.relay_first_required() || !self.config.relay.servers.is_empty(),
            bounded_birthday_allowed: self.config.network.birthday_probing_enabled
                && (local.birthday_candidate || remote.birthday_candidate),
            ..TraversalContext::default()
        };
        let plan = plan_traversal(&local, &remote, &context);
        (plan.strategy == p2pnet_nat::TraversalStrategy::HardHardSynchronizedCandidate).then_some(
            HardHardPlanSnapshot {
                local_network_generation: local_generation,
                remote_candidate_epoch: conn.remote_candidate_epoch(),
                local_profile_generation,
                remote_profile_generation,
            },
        )
    }

    pub(crate) async fn hard_hard_register_session(
        &self,
        record: HardHardSessionRecord,
    ) -> bool {
        let now = unix_time_millis();
        let mut sessions = self.hard_hard_sessions.lock().await;
        sessions.retain(|_, existing| existing.expires_at_ms >= now);
        let key = (record.peer_id.clone(), record.session_id.clone());
        if let Some(existing) = sessions.get(&key) {
            return existing.initiator == record.initiator
                && existing.local_network_generation == record.local_network_generation
                && existing.remote_candidate_epoch == record.remote_candidate_epoch
                && existing.local_profile_generation == record.local_profile_generation
                && existing.remote_profile_generation == record.remote_profile_generation;
        }
        // One live session per peer.  A newer fresh measurement supersedes
        // every older response fence before it can reuse an exact socket.
        sessions.retain(|(owner, session_id), _| {
            owner != &record.peer_id || session_id == &record.session_id
        });
        if sessions.len() >= MAX_HARD_HARD_SESSIONS {
            if let Some(oldest_key) = sessions
                .iter()
                .min_by_key(|(_, session)| session.created_at)
                .map(|(key, _)| key.clone())
            {
                sessions.remove(&oldest_key);
            }
        }
        sessions.insert(key, record);
        true
    }

    /// Look up a session by the stable token carried by either direction of
    /// the compact envelope.  The response swaps the directional generation
    /// fields, so reconstructing the initiator's full encoded string from the
    /// response would be both brittle and unnecessarily permissive.
    pub(crate) async fn hard_hard_session_by_token(
        &self,
        peer_id: &str,
        token: &str,
    ) -> Option<HardHardSessionRecord> {
        let now = unix_time_millis();
        let mut sessions = self.hard_hard_sessions.lock().await;
        sessions.retain(|_, existing| existing.expires_at_ms >= now);
        sessions
            .iter()
            .find(|((owner, session_id), _)| {
                owner == peer_id
                    && session_id
                        .split(':')
                        .nth(2)
                        .is_some_and(|session_token| session_token == token)
            })
            .map(|(_, record)| record.clone())
    }

    /// Atomically consume the one reciprocal-sweep slot for a session.  A
    /// duplicate response can arrive after the candidate transaction was
    /// already applied; it must not launch a second exact-socket sweep.
    pub(crate) async fn hard_hard_begin_sweep(
        &self,
        peer_id: &str,
        token: &str,
    ) -> Option<HardHardSessionRecord> {
        let now = unix_time_millis();
        let mut sessions = self.hard_hard_sessions.lock().await;
        sessions.retain(|_, existing| existing.expires_at_ms >= now);
        let (_, record) = sessions.iter_mut().find(|((owner, session_id), _)| {
            owner == peer_id
                && session_id
                    .split(':')
                    .nth(2)
                    .is_some_and(|session_token| session_token == token)
        })?;
        if record.state != HardHardSessionState::AwaitingPeer || record.attempt_count >= 1 {
            return None;
        }
        record.state = HardHardSessionState::Sweeping;
        record.attempt_count = record.attempt_count.saturating_add(1);
        Some(record.clone())
    }

    pub(crate) async fn hard_hard_remove_session(&self, peer_id: &str, session_id: &str) {
        self.hard_hard_sessions
            .lock()
            .await
            .remove(&(peer_id.to_string(), session_id.to_string()));
    }

    pub(crate) async fn clear_hard_hard_sessions(&self, peer_id: Option<&str>) {
        let mut sessions = self.hard_hard_sessions.lock().await;
        match peer_id {
            Some(peer_id) => sessions.retain(|(owner, _), _| owner != peer_id),
            None => sessions.clear(),
        }
    }
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
