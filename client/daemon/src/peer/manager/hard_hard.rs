// Hard↔Hard traversal admission and session fences.
//
// This file deliberately contains no socket sends and no path promotion. It
// only snapshots the authoritative planner inputs and keeps the short identity
// fence that lets the direct-runtime rendezvous reject an older response.

const MAX_HARD_HARD_SESSIONS: usize = 16;
const MAX_HARD_HARD_PREDICTION_TARGETS: usize = 256;

#[cfg(test)]
static HARD_HARD_TEST_NOW_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn set_hard_hard_test_now_ms(now_ms: Option<u64>) {
    HARD_HARD_TEST_NOW_MS.store(now_ms.unwrap_or(0), std::sync::atomic::Ordering::Release);
}

pub(crate) fn hard_hard_now_ms() -> u64 {
    #[cfg(test)]
    {
        let overridden = HARD_HARD_TEST_NOW_MS.load(std::sync::atomic::Ordering::Acquire);
        if overridden != 0 {
            return overridden;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardResponseAdmission {
    Ready,
    AlreadySweeping,
    Rejected,
}

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
        if !conn.remote_nat_profile_is_fresh()
            || !conn.remote_nat_profile_matches_candidate_epoch()
        {
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

    /// Return whether the authorized Hard↔Hard plan needs the bounded
    /// high-entropy lane. The profile/candidate generations are re-read by
    /// the normal plan fence, so this boolean is never used without the same
    /// identity snapshot.
    pub(crate) async fn hard_hard_plan_uses_birthday(&self, peer_id: &str) -> Option<bool> {
        let local_profile_generation = self.current_local_profile_generation_sync();
        let local_profile = self.local_nat_profile.read().await.clone()?;
        let local = NatCapabilities::from_profile(&local_profile)
            .with_profile_generation(local_profile_generation);
        let conn = self.connections.read().await.get(peer_id)?.clone();
        let remote_profile = conn.remote_nat_profile.as_ref()?;
        if !conn.online
            || conn.state == ConnectionState::Direct
            || !conn.remote_nat_profile_is_fresh()
            || !conn.remote_nat_profile_matches_candidate_epoch()
        {
            return None;
        }
        let remote = remote_profile
            .capabilities
            .clone()
            .with_profile_generation(remote_profile.generation?);
        if !local.is_hard_nat() || !remote.is_hard_nat() {
            return None;
        }
        let bounded = self.config.network.birthday_probing_enabled
            && (local.birthday_candidate || remote.birthday_candidate);
        Some(bounded
            && !(local.hard_allocation_is_predictable()
                && remote.hard_allocation_is_predictable()))
    }

    pub(crate) async fn hard_hard_register_session(
        &self,
        record: HardHardSessionRecord,
    ) -> bool {
        let now = hard_hard_now_ms();
        let mut cancelled = Vec::new();
        let mut retired_winners = Vec::new();
        let mut sessions = self.hard_hard_sessions.lock().await;
        let expired_keys = sessions
            .iter()
            .filter(|(_, existing)| {
                existing.state != HardHardSessionState::Retiring
                    && existing.expires_at_ms < now
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired_keys {
            if let Some(existing) = sessions.get_mut(&key) {
                existing.state = HardHardSessionState::Retiring;
                retired_winners.push((existing.peer_id.clone(), existing.session_token.clone()));
                cancelled.push(existing.cancellation.clone());
            }
        }
        let key = (record.peer_id.clone(), record.session_id.clone());
        let winner_key = (record.peer_id.clone(), record.session_token.clone());
        // `true` means THIS record became the authoritative owner. An exact
        // duplicate is accepted by the control-plane state machine, but it
        // must not make a second measurement believe it owns the existing
        // record's cleanup watcher. Returning false keeps that measurement's
        // provisional guard armed so its token-tagged socket rolls back.
        let inserted = if sessions.contains_key(&key) {
            false
        } else {
            // One live session per peer.  A newer fresh measurement supersedes
            // every older response fence before it can reuse an exact socket.
            let replaced_keys = sessions
                .iter()
                .filter(|(key, existing)| {
                    key.0 == record.peer_id
                        && existing.state != HardHardSessionState::Retiring
                })
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            for old_key in replaced_keys {
                if let Some(existing) = sessions.get_mut(&old_key) {
                    existing.state = HardHardSessionState::Retiring;
                    retired_winners
                        .push((existing.peer_id.clone(), existing.session_token.clone()));
                    cancelled.push(existing.cancellation.clone());
                }
            }
            let active_count = sessions
                .values()
                .filter(|session| session.state != HardHardSessionState::Retiring)
                .count();
            if active_count >= MAX_HARD_HARD_SESSIONS {
                if let Some(oldest_key) = sessions
                    .iter()
                    .filter(|(_, session)| session.state != HardHardSessionState::Retiring)
                    .min_by_key(|(_, session)| session.created_at)
                    .map(|(key, _)| key.clone())
                {
                    if let Some(existing) = sessions.get_mut(&oldest_key) {
                        existing.state = HardHardSessionState::Retiring;
                        retired_winners
                            .push((existing.peer_id.clone(), existing.session_token.clone()));
                        cancelled.push(existing.cancellation.clone());
                    }
                }
            }
            sessions.insert(key, record);
            true
        };
        drop(sessions);
        if inserted || !retired_winners.is_empty() {
            let mut winners = self.hard_hard_winners.lock().await;
            if inserted {
                winners.remove(&winner_key);
            }
            for key in retired_winners {
                winners.remove(&key);
            }
        }
        for cancellation in cancelled {
            cancellation.cancel_for_hard_hard_cleanup();
        }
        inserted
    }

    /// A live session suppresses a second initiator while its bounded socket
    /// and pending ACK evidence are still authoritative.
    pub(crate) async fn hard_hard_session_is_active(&self, peer_id: &str) -> bool {
        let now = hard_hard_now_ms();
        self.hard_hard_sessions.lock().await.iter().any(
            |((owner, _), record)| {
                owner == peer_id
                    && record.state != HardHardSessionState::Retiring
                    && !record.cancellation.is_cancelled()
                    && record.expires_at_ms >= now
            },
        )
    }

    /// Snapshot one live Hard↔Hard record for the deterministic two-peer
    /// acceptance harness. Runtime callers use the narrower identity-fence
    /// predicates below; this test-only view lets E2E assertions correlate the
    /// measured socket with the session ledger without adding a production
    /// data path.
    #[cfg(test)]
    pub(crate) async fn hard_hard_session_for_test(
        &self,
        peer_id: &str,
    ) -> Option<HardHardSessionRecord> {
        self.hard_hard_sessions
            .lock()
            .await
            .values()
            .find(|record| record.peer_id == peer_id)
            .cloned()
    }

    /// Pure exact snapshot used by the cleanup owner. Unlike the admission
    /// getters this intentionally includes a Retiring record so a cleanup
    /// task can retain the latest winner identity without reviving it.
    pub(crate) async fn hard_hard_session_snapshot_for_cleanup(
        &self,
        peer_id: &str,
        session_id: &str,
        session_token: &str,
    ) -> Option<HardHardSessionRecord> {
        self.hard_hard_sessions
            .lock()
            .await
            .get(&(peer_id.to_string(), session_id.to_string()))
            .filter(|record| {
                record.peer_id == peer_id && record.session_token == session_token
            })
            .cloned()
    }

    /// Claim the single cleanup watcher for one exact session. The claim is
    /// separate from the session ledger so duplicate signal handling cannot
    /// spawn a second old cleanup owner.
    pub(crate) async fn hard_hard_claim_cleanup_owner(
        &self,
        peer_id: &str,
        session_id: &str,
        session_token: &str,
    ) -> bool {
        self.hard_hard_cleanup_owners
            .lock()
            .await
            .insert((
                peer_id.to_string(),
                session_id.to_string(),
                session_token.to_string(),
            ))
    }

    #[cfg(test)]
    pub(crate) async fn hard_hard_cleanup_owner_claimed_for_test(
        &self,
        peer_id: &str,
        session_id: &str,
        session_token: &str,
    ) -> bool {
        self.hard_hard_cleanup_owners
            .lock()
            .await
            .contains(&(
                peer_id.to_string(),
                session_id.to_string(),
                session_token.to_string(),
            ))
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
        let now = hard_hard_now_ms();
        self.hard_hard_sessions
            .lock()
            .await
            .iter()
            .find(|((owner, _), record)| {
                owner == peer_id
                    && record.session_token == token
                    && record.state != HardHardSessionState::Retiring
                    && !record.cancellation.is_cancelled()
                    && record.expires_at_ms >= now
            })
            .map(|(_, record)| record.clone())
    }

    /// Promote one authenticated speculative socket to the session winner.
    ///
    /// The UDP layer has already authenticated the Probe v2 packet and checked
    /// the socket's local token tag. This manager-side fence makes the first
    /// valid peer-reflexive observation sticky: a delayed packet from another
    /// candidate can add evidence, but cannot replace the selected socket.
    pub(crate) async fn hard_hard_select_winner(
        &self,
        peer_id: &str,
        token: &str,
        socket_index: usize,
        network_generation: u64,
        punch_generation: u64,
        socket_local_endpoint: SocketAddr,
    ) -> Option<HardHardFreshSocketIdentity> {
        let now = hard_hard_now_ms();
        let key = (peer_id.to_string(), token.to_string());
        // Keep the session record locked through the sticky-winner update.
        // Every other path either takes `hard_hard_sessions` first or drops
        // it before touching `hard_hard_winners`, so this ordering cannot
        // deadlock. More importantly, cancellation can no longer leave a
        // winner map entry behind after the eligible-session check but before
        // the exact fresh-socket identity is committed to the record.
        let mut sessions = self.hard_hard_sessions.lock().await;
        let record = sessions.values_mut().find(|record| {
                record.peer_id == peer_id
                    && record.session_token == token
                    && record.state != HardHardSessionState::Retiring
                    && !record.cancellation.is_cancelled()
                    && record.expires_at_ms >= now
                    && record.local_network_generation == network_generation
                    && (record.state == HardHardSessionState::Sweeping
                        || (!record.initiator && record.state == HardHardSessionState::AwaitingPeer))
            })?;
        let mut winners = self.hard_hard_winners.lock().await;
        if let Some(existing) = winners.get(&key) {
            if *existing != socket_index {
                return None;
            }
        } else {
            winners.insert(key, socket_index);
        }
        record.fresh_socket.socket_index = socket_index;
        record.fresh_socket.punch_generation = punch_generation.max(1);
        record.fresh_socket.socket_local_endpoint = socket_local_endpoint;
        Some(record.fresh_socket.clone())
    }

    /// Read the current socket identity after a peer-reflexive winner may have
    /// replaced the initially measured socket.
    pub(crate) async fn hard_hard_fresh_socket_for_token(
        &self,
        peer_id: &str,
        token: &str,
    ) -> Option<HardHardFreshSocketIdentity> {
        self.hard_hard_session_by_token(peer_id, token)
            .await
            .map(|record| record.fresh_socket)
    }

    /// Return whether this bounded session has already selected a winner.
    /// Dynamic-socket workers use the sticky ledger as their cancellation
    /// fence so a peer-reflexive packet stops the remaining scatter workers
    /// before they emit another candidate.
    pub(crate) async fn hard_hard_winner_for_token(
        &self,
        peer_id: &str,
        token: &str,
    ) -> Option<usize> {
        self.hard_hard_winners
            .lock()
            .await
            .get(&(peer_id.to_string(), token.to_string()))
            .copied()
    }

    /// Hold the sticky-winner writer for deterministic cancellation tests.
    #[cfg(test)]
    pub(crate) async fn hold_hard_hard_winner_writer_for_test(
        &self,
    ) -> tokio::sync::MutexGuard<'_, HashMap<(String, String), usize>> {
        self.hard_hard_winners.lock().await
    }

    /// Admit the one expected reciprocal response after the remote candidate
    /// epoch advances.  A fresh response is allowed to move the session's
    /// remote-candidate fence by exactly one epoch; the socket identity is
    /// updated with that same epoch before the runtime can sweep it.  A
    /// retransmission after the sweep has started is harmless and does not
    /// cancel the in-flight session.
    pub(crate) async fn hard_hard_prepare_response(
        &self,
        peer_id: &str,
        token: &str,
        current_remote_candidate_epoch: u64,
    ) -> HardHardResponseAdmission {
        let now = hard_hard_now_ms();
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some((_, record)) = sessions
            .iter_mut()
            .find(|((owner, _), record)| {
                owner == peer_id
                    && record.session_token == token
                    && record.state != HardHardSessionState::Retiring
                    && !record.cancellation.is_cancelled()
                    && record.expires_at_ms >= now
            })
        else {
            return HardHardResponseAdmission::Rejected;
        };
        if !record.initiator {
            return HardHardResponseAdmission::Rejected;
        }
        if record.state == HardHardSessionState::Sweeping {
            return HardHardResponseAdmission::AlreadySweeping;
        }
        if record.state != HardHardSessionState::AwaitingPeer || record.attempt_count >= 1 {
            return HardHardResponseAdmission::Rejected;
        }
        let expected_next = record.remote_candidate_epoch.wrapping_add(1).max(1);
        if current_remote_candidate_epoch != record.remote_candidate_epoch
            && current_remote_candidate_epoch != expected_next
        {
            return HardHardResponseAdmission::Rejected;
        }
        record.remote_candidate_epoch = current_remote_candidate_epoch;
        record.fresh_socket.remote_candidate_epoch = current_remote_candidate_epoch;
        HardHardResponseAdmission::Ready
    }

    /// Probe ACKs carry this opaque token in a local-only binding.  The
    /// manager is the authority that decides whether the token still belongs
    /// to the current bounded rendezvous; a removed/superseded session cannot
    /// be resurrected by a delayed authenticated ACK.
    pub(crate) async fn hard_hard_session_token_is_current(
        &self,
        peer_id: &str,
        token: &str,
    ) -> bool {
        let now = hard_hard_now_ms();
        let sessions = self.hard_hard_sessions.lock().await;
        sessions.values().any(|record| {
            record.peer_id == peer_id
                && record.session_token == token
                && record.state != HardHardSessionState::Retiring
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= now
            })
    }

    /// Return true only while every stamped identity fence of a Hard↔Hard
    /// session still matches the live manager state.  This is deliberately
    /// stronger than the token-only send fence: the final Direct verdict must
    /// not be able to reuse a socket after a candidate/profile refresh or a
    /// superseding session.
    pub(crate) async fn hard_hard_session_identity_is_current(
        &self,
        identity: &HardHardFreshSocketIdentity,
    ) -> bool {
        let now = hard_hard_now_ms();
        let record = {
            let sessions = self.hard_hard_sessions.lock().await;
            sessions
                .values()
                .find(|record| {
                    record.peer_id == identity.peer_id
                        && record.session_token == identity.session_token
                        && record.state != HardHardSessionState::Retiring
                        && !record.cancellation.is_cancelled()
                        && record.expires_at_ms >= now
                })
                .cloned()
        };
        let Some(record) = record else {
            return false;
        };
        if record.local_network_generation != identity.network_generation
            || record.remote_candidate_epoch != identity.remote_candidate_epoch
            || record.local_profile_generation != identity.local_profile_generation
            || record.remote_profile_generation != identity.remote_profile_generation
            || record.fresh_socket != *identity
        {
            return false;
        }
        if self.current_network_generation_sync() != identity.network_generation
            || self.current_local_profile_generation_sync() != identity.local_profile_generation
        {
            return false;
        }

        let connections = self.connections.read().await;
        let Some(conn) = connections.get(&identity.peer_id) else {
            return false;
        };
        conn.online
            && conn.remote_candidate_epoch() == identity.remote_candidate_epoch
            && conn.remote_nat_profile_is_fresh()
            && conn.remote_nat_profile_candidate_epoch == Some(identity.remote_candidate_epoch)
            && conn
                .remote_nat_profile
                .as_ref()
                .and_then(|profile| profile.generation)
                == Some(identity.remote_profile_generation)
    }

    /// Confirmation-time session fence that never waits on `connections`.
    /// The full asynchronous predicate above remains the cleanup/diagnostic
    /// authority; the grace timer uses this version because the Direct commit
    /// mirror and UDP socket proof already carry the state that was validated
    /// under the connection writer.  A connection-map writer therefore cannot
    /// delay the confirmation start or consume its bounded grace.
    pub(crate) async fn hard_hard_session_identity_is_current_for_confirmation(
        &self,
        identity: &HardHardFreshSocketIdentity,
    ) -> bool {
        let now = hard_hard_now_ms();
        let record = self
            .hard_hard_sessions
            .lock()
            .await
            .values()
            .find(|record| {
                record.peer_id == identity.peer_id
                    && record.session_token == identity.session_token
                    && record.state != HardHardSessionState::Retiring
                    && !record.cancellation.is_cancelled()
                    && record.expires_at_ms >= now
            })
            .cloned();
        let Some(record) = record else {
            return false;
        };
        record.local_network_generation == identity.network_generation
            && record.remote_candidate_epoch == identity.remote_candidate_epoch
            && record.local_profile_generation == identity.local_profile_generation
            && record.remote_profile_generation == identity.remote_profile_generation
            && record.fresh_socket == *identity
            && self.current_network_generation_sync() == identity.network_generation
            && self.current_local_profile_generation_sync() == identity.local_profile_generation
    }

    /// Return true when the current authoritative Direct state selected a pair
    /// on this socket's exact local endpoint and current candidate epoch.  The
    /// UDP layer separately proves affinity and authenticated socket evidence;
    /// keeping this half in the manager reuses the existing Direct state and
    /// candidate-pair authorities without introducing another Direct state.
    pub(crate) async fn hard_hard_direct_pair_is_current(
        &self,
        identity: &HardHardFreshSocketIdentity,
    ) -> bool {
        if self.current_network_generation_sync() != identity.network_generation {
            return false;
        }
        let connections = self.connections.read().await;
        let Some(conn) = connections.get(&identity.peer_id) else {
            return false;
        };
        conn.state == ConnectionState::Direct
            && conn.direct_generation == identity.network_generation
            && conn.candidate_pairs.iter().any(|pair| {
                pair.local_generation == identity.network_generation
                    && pair.remote_candidate_epoch == identity.remote_candidate_epoch
                    && pair.state == CandidatePairState::Selected
                    && pair.selected_at.is_some()
                    && pair.local_endpoint == Some(identity.socket_local_endpoint)
            })
    }

    /// Return true only when the authoritative Direct commit selected a pair
    /// on this Hard↔Hard socket and the full session/generation/profile fence
    /// is still current.  The UDP layer separately proves affinity and
    /// authenticated socket evidence.
    pub(crate) async fn hard_hard_direct_confirmation_is_current(
        &self,
        identity: &HardHardFreshSocketIdentity,
    ) -> bool {
        self.hard_hard_session_identity_is_current(identity).await
            && self.hard_hard_direct_pair_is_current(identity).await
    }

    /// Atomically consume the one reciprocal-sweep slot for a session.  A
    /// duplicate response can arrive after the candidate transaction was
    /// already applied; it must not launch a second exact-socket sweep.
    pub(crate) async fn hard_hard_begin_sweep(
        &self,
        peer_id: &str,
        token: &str,
        remote_prediction: Vec<SocketAddr>,
        remote_prediction_confidence: u8,
        remote_network_generation: u64,
    ) -> Option<HardHardSessionRecord> {
        if remote_prediction.is_empty()
            || remote_prediction.len() > MAX_HARD_HARD_PREDICTION_TARGETS
            || remote_prediction_confidence == 0
        {
            return None;
        }
        let now = hard_hard_now_ms();
        let mut sessions = self.hard_hard_sessions.lock().await;
        let (_, record) = sessions
            .iter_mut()
            .find(|((owner, _), record)| {
                owner == peer_id
                    && record.session_token == token
                    && record.state != HardHardSessionState::Retiring
                    && !record.cancellation.is_cancelled()
                    && record.expires_at_ms >= now
            })?;
        if record.state != HardHardSessionState::AwaitingPeer || record.attempt_count >= 1 {
            return None;
        }
        if record.remote_network_generation != 0
            && remote_network_generation != 0
            && record.remote_network_generation != remote_network_generation
        {
            return None;
        }
        record.remote_prediction = remote_prediction;
        record.remote_prediction_confidence = remote_prediction_confidence;
        if record.remote_network_generation == 0 {
            record.remote_network_generation = remote_network_generation;
        }
        record.state = HardHardSessionState::Sweeping;
        record.attempt_count = record.attempt_count.saturating_add(1);
        Some(record.clone())
    }

    /// Move one exact session into the cleanup phase.  Retirement is a
    /// synchronous ownership handoff: the record remains in the ledger until
    /// the transport owner confirms that token-scoped socket/pending cleanup
    /// is complete.  Repeating the request is harmless.
    pub(crate) async fn hard_hard_retire_session(
        &self,
        peer_id: &str,
        session_id: &str,
        session_token: &str,
    ) -> bool {
        let cancellation = {
            let mut sessions = self.hard_hard_sessions.lock().await;
            let Some(record) = sessions
                .get_mut(&(peer_id.to_string(), session_id.to_string()))
                .filter(|record| record.session_token == session_token)
            else {
                return false;
            };
            record.state = HardHardSessionState::Retiring;
            record.cancellation.clone()
        };
        self.hard_hard_winners
            .lock()
            .await
            .remove(&(peer_id.to_string(), session_token.to_string()));
        cancellation.cancel_for_hard_hard_cleanup();
        true
    }

    /// Remove an exact retired record after the UDP cleanup transaction has
    /// completed.  A stale cleanup can never delete a replacement because the
    /// session ID and token are both checked while holding the ledger lock.
    pub(crate) async fn hard_hard_complete_session_cleanup(
        &self,
        peer_id: &str,
        session_id: &str,
        session_token: &str,
    ) -> bool {
        let removed = {
            let mut sessions = self.hard_hard_sessions.lock().await;
            let key = (peer_id.to_string(), session_id.to_string());
            sessions.get(&key).is_some_and(|record| {
                record.session_token == session_token
                    && record.state == HardHardSessionState::Retiring
            }) && sessions.remove(&key).is_some()
        };
        if removed {
            self.hard_hard_winners
                .lock()
                .await
                .remove(&(peer_id.to_string(), session_token.to_string()));
            self.hard_hard_cleanup_owners
                .lock()
                .await
                .remove(&(
                    peer_id.to_string(),
                    session_id.to_string(),
                    session_token.to_string(),
                ));
        }
        removed
    }

    #[cfg(test)]
    pub(crate) fn install_hard_hard_cleanup_gate_for_test(
        &self,
        peer_id: &str,
        session_id: &str,
        session_token: &str,
    ) -> (Arc<HardHardCleanupGate>, HardHardCleanupGateGuard) {
        let gate = Arc::new(HardHardCleanupGate::new());
        let mut slot = self
            .hard_hard_cleanup_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = slot.replace(HardHardCleanupGateRegistration {
            peer_id: peer_id.to_string(),
            session_id: session_id.to_string(),
            session_token: session_token.to_string(),
            gate: gate.clone(),
        });
        drop(slot);
        (
            gate.clone(),
            HardHardCleanupGateGuard {
                slot: self.hard_hard_cleanup_gate.clone(),
                installed: gate,
                previous,
            },
        )
    }

    #[cfg(test)]
    pub(crate) async fn pause_hard_hard_cleanup_for_test(
        &self,
        peer_id: &str,
        session_id: &str,
        session_token: &str,
    ) {
        let gate = self
            .hard_hard_cleanup_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|registration| {
                registration.peer_id == peer_id
                    && registration.session_id == session_id
                    && registration.session_token == session_token
            })
            .map(|registration| registration.gate.clone());
        if let Some(gate) = gate {
            gate.signal_reached();
            gate.wait_for_release().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn signal_hard_hard_cleanup_completed_for_test(
        &self,
        peer_id: &str,
        session_id: &str,
        session_token: &str,
    ) {
        let gate = self
            .hard_hard_cleanup_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|registration| {
                registration.peer_id == peer_id
                    && registration.session_id == session_id
                    && registration.session_token == session_token
            })
            .map(|registration| registration.gate.clone());
        if let Some(gate) = gate {
            gate.signal_completed();
        }
    }

    pub(crate) async fn clear_hard_hard_sessions(&self, peer_id: Option<&str>) {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let retiring = match peer_id {
            Some(peer_id) => sessions
                .iter()
                .filter(|((owner, _), _)| owner == peer_id)
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>(),
            None => sessions.keys().cloned().collect::<Vec<_>>(),
        };
        let retired_tokens = retiring
            .iter()
            .filter_map(|key| sessions.get(key).map(|record| (key.0.clone(), record.session_token.clone())))
            .collect::<Vec<_>>();
        let mut cancellations = Vec::with_capacity(retired_tokens.len());
        for key in retiring {
            if let Some(record) = sessions.get_mut(&key) {
                if record.state != HardHardSessionState::Retiring {
                    record.state = HardHardSessionState::Retiring;
                    cancellations.push(record.cancellation.clone());
                }
            }
        }
        drop(sessions);
        let mut winners = self.hard_hard_winners.lock().await;
        for key in retired_tokens {
            winners.remove(&key);
        }
        drop(winners);
        for cancellation in cancellations {
            cancellation.cancel_for_hard_hard_cleanup();
        }
    }
}
