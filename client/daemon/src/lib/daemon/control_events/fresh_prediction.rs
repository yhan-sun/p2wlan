/// Whether an offer/answer carries a fresh-mapping prediction window.
///
/// Ordinary ICE gathering emits `predicted` candidate labels, so only the
/// distinct `predicted_fresh:<boot_epoch>:<punch_generation>` label counts as
/// a fresh prediction.  The embedded incarnation+generation orders
/// predictions by NAT measurement generation instead of by HTTP send time: a
/// superseded task that sends late cannot masquerade as a newer prediction,
/// and a restarted daemon incarnation supersedes the old one.  Signals
/// without the label (old clients, ordinary refreshes) degrade to an ordinary
/// synchronized punch session.
///
/// Every fresh label in one payload must agree: when the payload mixes two
/// different valid identities the signal is inconsistent and is rejected
/// deterministically instead of letting HashMap iteration pick an arbitrary
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreshPredictionSources {
    None,
    Valid(crate::FreshPredictionId),
    Malformed,
    Conflicting,
}

fn fresh_prediction_from_sources(
    candidate_sources: &HashMap<String, String>,
) -> FreshPredictionSources {
    let mut found = None;
    for source in candidate_sources.values() {
        if !source.starts_with(crate::FRESH_PREDICTION_SOURCE_LABEL_PREFIX) {
            continue;
        }
        let Some(id) = crate::parse_fresh_prediction_source_label(source) else {
            return FreshPredictionSources::Malformed;
        };
        match found {
            None => found = Some(id),
            Some(previous) if previous == id => {}
            Some(_) => return FreshPredictionSources::Conflicting,
        }
    }
    match found {
        Some(id) => FreshPredictionSources::Valid(id),
        None => FreshPredictionSources::None,
    }
}

#[derive(Debug, Clone, Copy)]
enum FreshCandidateTransactionResult {
    Committed,
    NotApplied(CandidateSetApplyResult),
    Superseded,
    Contended,
}

/// What punch may start from a fresh-prediction signal.
#[derive(Debug, Clone)]
enum FreshPunchDecision {
    /// No fresh prediction: an ordinary signal.
    None,
    /// The committed fresh snapshot is valid (present, unexpired, non-empty):
    /// the immutable targets may be punched at FRESH priority.
    Fresh(crate::FreshPredictionId, Vec<SocketAddr>),
    /// The signal carried a fresh label but its committed snapshot is expired
    /// or empty: it must NOT claim fresh priority and must NOT fall back to
    /// the shared candidate set as if it were a fresh prediction.  Only a
    /// handshake-carrying signal may degrade to an ORDINARY priority punch
    /// over the shared candidates; a candidate-only signal is ignored.
    Degraded,
    /// A fresh label was present but its authenticated identity or candidate
    /// transaction was rejected. Ordinary non-Hard↔Hard callers retain their
    /// prior handshake fallback; the Hard↔Hard admission path records the
    /// precise rejection and remains fail-closed.
    Rejected(FreshPunchRejection),
}

impl Daemon {
    /// Freeze the immutable candidate snapshot bound to a fresh identity.
    ///
    /// The snapshot is the payload the identity was committed with (stored by
    /// the commit transaction) — never the current ordinary refresh set and
    /// never a retry's possibly-reordered payload: a later ordinary refresh
    /// must never change the targets of a running fresh session.  The
    /// snapshot's own expiry deadline is honored: an idempotent retry of an
    /// already-recorded identity must never punch toward prediction ports
    /// that have expired since the commit.
    async fn freeze_fresh_punch_targets(
        &self,
        from_node_id: &str,
        id: crate::FreshPredictionId,
    ) -> Option<Vec<SocketAddr>> {
        let snapshot = self
            .peers
            .remote_fresh_snapshot_for(from_node_id, id)
            .await?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if snapshot.candidates_expires_at_ms.is_some_and(|expires_at| {
            expires_at.saturating_add(crate::peer::CANDIDATE_EXPIRY_CLOCK_SKEW_GRACE_MS) <= now_ms
        }) {
            debug!(
                "Fresh-mapping prediction {id:?} from {from_node_id} expired since its commit; no punch starts from it"
            );
            return None;
        }
        let targets = snapshot
            .fresh_candidates
            .iter()
            .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return None;
        }
        Some(targets)
    }

    /// Whether a signal's server-bound sender identity fingerprint matches
    /// the peer's CURRENT public key.
    ///
    /// The control server binds every queued signal to the sender's identity
    /// fingerprint at send time.  When the peer later changes its public key
    /// (rejoin as a new identity), signals that were still queued from the
    /// OLD identity carry the old fingerprint: they must never enter the new
    /// identity's fresh-prediction high-water space, so their fresh labels
    /// are treated as stale.  Signals without a fingerprint (old server) or
    /// for a peer without a recorded public key are conservatively treated as
    /// matching (no identity information to contradict them).
    fn signal_sender_identity_matches_peer(
        &self,
        peer_id: &str,
        sender_public_key: Option<&str>,
    ) -> bool {
        self.peers
            .signal_sender_identity_matches_peer_sync(peer_id, sender_public_key)
    }

    /// The prepare/apply/commit transaction for one fresh signal, shared by
    /// the offer and answer paths.
    ///
    /// 1. prepare compares the identity against the peer's high-water AND
    ///    verifies an equal-id retry's payload against the committed
    ///    snapshot (payload mismatch is rejected).
    /// 2. apply installs the candidates and records the apply.
    /// 3. commit is a strict CAS (`id > current`): exactly one concurrent
    ///    commit of an identity wins and freezes its immutable snapshot; the
    ///    loser rolls its own apply back and starts no punch.
    #[allow(clippy::too_many_arguments)]
    async fn fresh_prediction_transaction(
        &self,
        from_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
        sender_public_key: Option<&str>,
        retry_contention_in_candidate_lane: bool,
    ) -> (
        FreshSignalVerdict,
        CandidateSetApplyResult,
        FreshPunchDecision,
    ) {
        let fresh_verdict = match fresh_prediction_from_sources(candidate_sources) {
            FreshPredictionSources::Conflicting => {
                self.peers
                    .record_direct_event(
                        from_node_id,
                        "fresh_prediction_inconsistent",
                        None,
                        Some(candidates.len()),
                        None,
                        "offer carried conflicting fresh-mapping prediction labels; candidates ignored",
                    )
                    .await;
                FreshSignalVerdict::Inconsistent
            }
            FreshPredictionSources::Malformed => {
                self.peers
                    .record_direct_event(
                        from_node_id,
                        "fresh_prediction_label_malformed",
                        None,
                        Some(candidates.len()),
                        None,
                        "candidate source claimed the fresh-prediction label namespace but did not parse; fresh admission rejected",
                    )
                    .await;
                FreshSignalVerdict::Malformed
            }
            FreshPredictionSources::None => FreshSignalVerdict::None,
            FreshPredictionSources::Valid(id) => {
                let signal_identity_matches =
                    self.signal_sender_identity_matches_peer(from_node_id, sender_public_key);
                if !signal_identity_matches {
                    // The signal was bound by the control server to a sender
                    // identity fingerprint that is NOT the peer's current
                    // public key (the peer changed key and this is a stale
                    // queued signal from the old identity): its fresh label
                    // must never enter the NEW identity's high-water space.
                    self.peers
                        .record_direct_event(
                            from_node_id,
                            "fresh_prediction_stale_identity",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "offer carried fresh-mapping prediction {id:?} from a stale sender identity; fresh candidates ignored"
                            ),
                        )
                        .await;
                    FreshSignalVerdict::StaleIdentity
                } else {
                    match self
                        .peers
                        .prepare_remote_fresh_prediction(
                            from_node_id,
                            id,
                            candidates,
                            candidate_sources,
                            candidates_expires_at_ms,
                        )
                        .await
                    {
                        crate::peer::RemoteFreshAdmission::Accepted => {
                            FreshSignalVerdict::Accepted(id)
                        }
                        crate::peer::RemoteFreshAdmission::AlreadyRecorded => {
                            self.peers
                                .record_direct_event(
                                    from_node_id,
                                    "fresh_prediction_retry",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "offer is an idempotent retry of the committed fresh-mapping prediction {id:?}; candidates are not re-applied"
                                    ),
                                )
                                .await;
                            FreshSignalVerdict::AlreadyRecorded(id)
                        }
                        crate::peer::RemoteFreshAdmission::PayloadMismatch => {
                            self.peers
                                .record_direct_event(
                                    from_node_id,
                                    "fresh_prediction_payload_mismatch",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "offer retries the committed fresh-mapping prediction {id:?} with a different candidate payload/expiry; rejected"
                                    ),
                                )
                                .await;
                            FreshSignalVerdict::PayloadMismatch(id)
                        }
                        crate::peer::RemoteFreshAdmission::Stale => {
                            self.peers
                                .record_direct_event(
                                    from_node_id,
                                    "fresh_prediction_stale",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "offer carried a superseded fresh-mapping prediction {id:?}; candidates ignored"
                                    ),
                                )
                                .await;
                            FreshSignalVerdict::Stale
                        }
                    }
                }
            }
        };
        let (candidate_apply_result, fresh_punch) = match fresh_verdict {
            FreshSignalVerdict::None => (
                self.peers
                    .add_candidates_with_metadata_for_identity(
                        from_node_id,
                        candidates,
                        candidate_sources,
                        candidate_generation,
                        candidates_expires_at_ms,
                        sender_public_key,
                    )
                    .await,
                FreshPunchDecision::None,
            ),
            FreshSignalVerdict::Malformed => (
                CandidateSetApplyResult::IgnoredStale,
                FreshPunchDecision::Rejected(FreshPunchRejection::MalformedLabel),
            ),
            FreshSignalVerdict::Accepted(id) => {
                let transaction = if retry_contention_in_candidate_lane {
                    match self
                        .peers
                        .try_apply_and_commit_remote_fresh_prediction_for_identity(
                            from_node_id,
                            id,
                            candidates,
                            candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                            sender_public_key,
                        )
                        .await
                    {
                        crate::peer::RemoteFreshTryTransactionOutcome::Committed => {
                            FreshCandidateTransactionResult::Committed
                        }
                        crate::peer::RemoteFreshTryTransactionOutcome::NotApplied(result) => {
                            FreshCandidateTransactionResult::NotApplied(result)
                        }
                        crate::peer::RemoteFreshTryTransactionOutcome::Superseded => {
                            FreshCandidateTransactionResult::Superseded
                        }
                        crate::peer::RemoteFreshTryTransactionOutcome::ContendedTransaction
                        | crate::peer::RemoteFreshTryTransactionOutcome::ContendedEpoch
                        | crate::peer::RemoteFreshTryTransactionOutcome::ContendedConnections => {
                            FreshCandidateTransactionResult::Contended
                        }
                    }
                } else {
                    match self
                        .peers
                        .apply_and_commit_remote_fresh_prediction_for_identity(
                            from_node_id,
                            id,
                            candidates,
                            candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                            sender_public_key,
                        )
                        .await
                    {
                        crate::peer::RemoteFreshTransactionOutcome::Committed => {
                            FreshCandidateTransactionResult::Committed
                        }
                        crate::peer::RemoteFreshTransactionOutcome::NotApplied(result) => {
                            FreshCandidateTransactionResult::NotApplied(result)
                        }
                        crate::peer::RemoteFreshTransactionOutcome::Superseded => {
                            FreshCandidateTransactionResult::Superseded
                        }
                    }
                };
                match transaction {
                    FreshCandidateTransactionResult::NotApplied(apply_result) => {
                        // PeerMissing, empty, expired or a stale candidate
                        // generation: the fresh ID is NOT consumed so the same
                        // signal retried later (after the peer registers, for
                        // example) still applies.
                        self.peers
                        .record_direct_event(
                            from_node_id,
                            "fresh_prediction_not_applied",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "fresh prediction {id:?} was not applied ({apply_result:?}); the fresh identity stays unconsumed"
                            ),
                        )
                        .await;
                        (
                            apply_result,
                            FreshPunchDecision::Rejected(
                                FreshPunchRejection::CandidateSetNotApplied(apply_result),
                            ),
                        )
                    }
                    FreshCandidateTransactionResult::Committed => {
                        // The identity is committed with an immutable snapshot:
                        // the punch targets are frozen from THAT snapshot.
                        let frozen = self.freeze_fresh_punch_targets(from_node_id, id).await;
                        let decision = match frozen {
                            Some(targets) => FreshPunchDecision::Fresh(id, targets),
                            // The committed snapshot expired or is empty: the
                            // prediction must never claim fresh priority or fall
                            // back to the shared candidates as if it were fresh.
                            None => {
                                self.peers
                                .record_direct_event(
                                    from_node_id,
                                    "fresh_prediction_snapshot_invalid",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "fresh prediction {id:?} committed but its snapshot is expired or empty; the signal degrades to ordinary priority"
                                    ),
                                )
                                .await;
                                FreshPunchDecision::Degraded
                            }
                        };
                        (CandidateSetApplyResult::Applied, decision)
                    }
                    FreshCandidateTransactionResult::Superseded => {
                        // A same-or-newer identity committed after this worker's
                        // optimistic prepare. The serialized transaction rejects
                        // this worker before it can replace the winner's candidates.
                        self.peers
                        .record_direct_event(
                            from_node_id,
                            "fresh_prediction_superseded",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "fresh prediction {id:?} was superseded before candidate mutation; no punch starts from it"
                            ),
                        )
                        .await;
                        (
                            CandidateSetApplyResult::IgnoredStale,
                            FreshPunchDecision::Rejected(FreshPunchRejection::Superseded),
                        )
                    }
                    FreshCandidateTransactionResult::Contended => {
                        return (
                            FreshSignalVerdict::Contended,
                            CandidateSetApplyResult::IgnoredStale,
                            FreshPunchDecision::Rejected(FreshPunchRejection::Contended),
                        );
                    }
                }
            }
            FreshSignalVerdict::AlreadyRecorded(id) => {
                // The candidates were applied by the first attempt; the punch
                // may still start from the committed snapshot — but only a
                // valid (unexpired, non-empty) snapshot may claim fresh
                // priority.
                let frozen = self.freeze_fresh_punch_targets(from_node_id, id).await;
                let decision = match frozen {
                    Some(targets) => FreshPunchDecision::Fresh(id, targets),
                    None => {
                        self.peers
                            .record_direct_event(
                                from_node_id,
                                "fresh_prediction_snapshot_invalid",
                                None,
                                Some(candidates.len()),
                                None,
                                format!(
                                    "fresh prediction retry {id:?} has an expired or empty committed snapshot; the signal degrades to ordinary priority"
                                ),
                            )
                            .await;
                        FreshPunchDecision::Degraded
                    }
                };
                (CandidateSetApplyResult::Applied, decision)
            }
            FreshSignalVerdict::PayloadMismatch(id) => {
                debug!(
                    "Fresh-mapping prediction {id:?} from {from_node_id} was rejected: the retry payload differs from the committed snapshot"
                );
                (
                    CandidateSetApplyResult::IgnoredStale,
                    FreshPunchDecision::Rejected(FreshPunchRejection::PayloadMismatch),
                )
            }
            FreshSignalVerdict::StaleIdentity => (
                CandidateSetApplyResult::IgnoredStale,
                FreshPunchDecision::Rejected(FreshPunchRejection::StaleSenderIdentity),
            ),
            FreshSignalVerdict::Stale => (
                CandidateSetApplyResult::IgnoredStale,
                FreshPunchDecision::Rejected(FreshPunchRejection::StalePrediction),
            ),
            FreshSignalVerdict::Inconsistent => {
                // The current candidate set stays authoritative; only the
                // handshake below may proceed.
                (
                    CandidateSetApplyResult::IgnoredStale,
                    FreshPunchDecision::Rejected(FreshPunchRejection::ConflictingLabels),
                )
            }
            FreshSignalVerdict::Contended => (
                CandidateSetApplyResult::IgnoredStale,
                FreshPunchDecision::Rejected(FreshPunchRejection::Contended),
            ),
        };
        (fresh_verdict, candidate_apply_result, fresh_punch)
    }
}
