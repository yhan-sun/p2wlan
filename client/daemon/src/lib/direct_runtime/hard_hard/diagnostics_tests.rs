#[cfg(test)]
mod hard_hard_production_diagnostics_tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    fn offer(generation: u64, token: Option<&str>) -> PendingPeerOffer {
        PendingPeerOffer {
            nat_profile: None,
            from_node_id: "private-peer-identity".to_string(),
            candidates: vec!["198.51.100.77:45678".to_string()],
            candidate_sources: HashMap::new(),
            candidate_generation: generation,
            network_generation: 4,
            peer_session_generation: Some(crate::peer::PeerSessionGeneration::for_test(9)),
            candidates_expires_at_ms: None,
            sender_public_key: Some("private-public-key".to_string()),
            handshake_init: Vec::new(),
            punch_at_ms: Some(hard_hard_now_ms() + 3_500),
            punch_at_server_ms: None,
            session_id: token.map(|token| {
                HardHardCoordination {
                    v2: None,
                    role: HardHardRole::Initiator,
                    token: token.to_string(),
                    local_network_generation: 2,
                    remote_candidate_epoch: 7,
                    local_profile_generation: 12,
                    remote_profile_generation: 13,
                    local_prediction_confidence: 60,
                    remote_prediction_confidence: 60,
                    remote_network_generation: 4,
                    local_prediction_model: "fixed_step".to_string(),
                    remote_prediction_model: "fixed_step".to_string(),
                }
                .encode()
            }),
            probe_ephemeral_public_key: None,
            delivery_receipt: None,
        }
    }

    #[test]
    fn hard_hard_candidate_queue_protects_original_transcript_and_reports_supersession() {
        let mut ledger = PendingHandshakeState::default();
        let CandidateOfferWorkAdmission::Started(owner, _) =
            ledger.enqueue_candidate_offer_work(offer(1, None))
        else {
            panic!("owner");
        };
        assert!(matches!(
            ledger.enqueue_candidate_offer_work(offer(2, Some("a1"))),
            CandidateOfferWorkAdmission::Coalesced { .. }
        ));
        assert!(matches!(
            ledger.enqueue_candidate_offer_work(offer(3, None)),
            CandidateOfferWorkAdmission::Coalesced {
                reason: HardHardCandidateDiscardReason::OrdinaryCoalesced,
                ..
            }
        ));
        let mut replay = offer(4, Some("a1"));
        replay.candidates = vec!["198.51.100.88:50000".to_string()];
        replay.punch_at_ms = Some(hard_hard_now_ms() + 7_000);
        assert!(matches!(
            ledger.enqueue_candidate_offer_work(replay),
            CandidateOfferWorkAdmission::Coalesced {
                reason: HardHardCandidateDiscardReason::SameSessionPreserved,
                ..
            }
        ));
        let preserved = ledger
            .candidate_offer_workers
            .get("private-peer-identity")
            .unwrap()
            .queued
            .as_ref()
            .unwrap();
        assert_eq!(preserved.candidate_generation, 2);
        assert_eq!(preserved.candidates, ["198.51.100.77:45678"]);
        let CandidateOfferWorkAdmission::Coalesced {
            discarded: Some(old),
            reason,
        } = ledger.enqueue_candidate_offer_work(offer(5, Some("b2")))
        else {
            panic!("bounded replacement must return its displaced HH observation");
        };
        assert_eq!(reason, HardHardCandidateDiscardReason::Superseded);
        assert_eq!(old.candidate_generation, 2);
        assert_eq!(ledger.candidate_offer_workers.len(), 1);
        let next = ledger
            .finish_candidate_offer_work("private-peer-identity", owner.owner)
            .unwrap();
        assert_eq!(next.candidate_generation, 5);
        assert!(ledger
            .finish_candidate_offer_work("private-peer-identity", owner.owner)
            .is_none());
    }

    #[test]
    fn hard_hard_active_candidate_survives_ordinary_successor_until_original_deadline() {
        let mut ledger = PendingHandshakeState::default();
        let CandidateOfferWorkAdmission::Started(owner, mut active) =
            ledger.enqueue_candidate_offer_work(offer(1, Some("a1")))
        else {
            panic!("owner");
        };
        assert!(matches!(
            ledger.enqueue_candidate_offer_work(offer(2, None)),
            CandidateOfferWorkAdmission::Coalesced { .. }
        ));
        assert!(!ledger.candidate_offer_work_has_priority_successor(
            "private-peer-identity",
            owner.owner,
            &active
        ));
        assert!(ledger
            .take_queued_candidate_offer_work_before_commit(
                "private-peer-identity",
                owner.owner,
                &active
            )
            .is_none());
        active.punch_at_ms = Some(hard_hard_now_ms());
        assert!(ledger.candidate_offer_work_has_priority_successor(
            "private-peer-identity",
            owner.owner,
            &active
        ));
        assert_eq!(
            ledger
                .take_queued_candidate_offer_work_before_commit(
                    "private-peer-identity",
                    owner.owner,
                    &active
                )
                .unwrap()
                .candidate_generation,
            2
        );
    }

    fn replace_lifecycle(value: &mut PendingPeerOffer, field: u8) {
        match field {
            0 => value.sender_public_key = Some("replacement-public-key".to_string()),
            1 => value.network_generation += 1,
            2 => {
                value.peer_session_generation =
                    Some(crate::peer::PeerSessionGeneration::for_test(10));
            }
            3 => {
                // The wire incarnation fixture used by lifecycle tests: flag,
                // 41-bit incarnation, then the 21-bit candidate counter.
                value.candidate_generation = 0x4000_0000_0000_0000 | (7 << 21) | 2;
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn hard_hard_queued_priority_never_masks_identity_or_generation_replacement() {
        for field in 0..4 {
            for token in [None, Some("a1")] {
                let mut ledger = PendingHandshakeState::default();
                let CandidateOfferWorkAdmission::Started(owner, _) =
                    ledger.enqueue_candidate_offer_work(offer(1, None))
                else {
                    panic!("owner");
                };
                let _ = ledger.enqueue_candidate_offer_work(offer(2, Some("a1")));
                let mut replacement = offer(3, token);
                replace_lifecycle(&mut replacement, field);
                let expected_generation = replacement.candidate_generation;
                let CandidateOfferWorkAdmission::Coalesced {
                    discarded: Some(old),
                    reason: HardHardCandidateDiscardReason::Superseded,
                } = ledger.enqueue_candidate_offer_work(replacement)
                else {
                    panic!("lifecycle replacement must displace old HH, field={field}");
                };
                assert_eq!(old.candidate_generation, 2);
                assert_eq!(ledger.candidate_offer_workers.len(), 1);
                let replacement = ledger
                    .finish_candidate_offer_work("private-peer-identity", owner.owner)
                    .unwrap();
                assert_eq!(replacement.candidate_generation, expected_generation);
                assert!(ledger
                    .finish_candidate_offer_work("private-peer-identity", owner.owner)
                    .is_none());
            }
        }
    }

    #[test]
    fn hard_hard_active_priority_never_delays_replacement_lifecycle() {
        for field in 0..4 {
            for token in [None, Some("a1")] {
                let mut ledger = PendingHandshakeState::default();
                let CandidateOfferWorkAdmission::Started(owner, active) =
                    ledger.enqueue_candidate_offer_work(offer(1, Some("a1")))
                else {
                    panic!("owner");
                };
                let mut replacement = offer(2, token);
                replace_lifecycle(&mut replacement, field);
                let expected_generation = replacement.candidate_generation;
                let _ = ledger.enqueue_candidate_offer_work(replacement);
                assert!(ledger.candidate_offer_work_has_priority_successor(
                    "private-peer-identity",
                    owner.owner,
                    &active
                ));
                assert_eq!(
                    ledger
                        .take_queued_candidate_offer_work_before_commit(
                            "private-peer-identity",
                            owner.owner,
                            &active,
                        )
                        .unwrap()
                        .candidate_generation,
                    expected_generation
                );
            }
        }
    }

    #[test]
    fn hard_hard_active_replay_preserves_original_and_cannot_run_after_finish() {
        let mut ledger = PendingHandshakeState::default();
        let CandidateOfferWorkAdmission::Started(owner, active) =
            ledger.enqueue_candidate_offer_work(offer(1, Some("a1")))
        else {
            panic!("owner");
        };
        let original_deadline = active.punch_at_ms;
        let mut replay = offer(2, Some("a1"));
        replay.candidates = vec!["198.51.100.88:50000".into()];
        replay.punch_at_ms = Some(hard_hard_now_ms() + 7_000);
        let CandidateOfferWorkAdmission::Coalesced {
            discarded: Some(discarded),
            reason: HardHardCandidateDiscardReason::SameSessionPreserved,
        } = ledger.enqueue_candidate_offer_work(replay)
        else {
            panic!("active duplicate must be discarded instead of becoming a successor");
        };
        assert_eq!(discarded.candidate_generation, 2);
        assert_eq!(active.candidate_generation, 1);
        assert_eq!(active.punch_at_ms, original_deadline);
        assert_eq!(active.candidates, ["198.51.100.77:45678"]);
        assert!(!ledger.candidate_offer_work_has_priority_successor(
            "private-peer-identity",
            owner.owner,
            &active,
        ));
        assert!(ledger
            .finish_candidate_offer_work("private-peer-identity", owner.owner)
            .is_none());
        assert!(ledger.candidate_offer_workers.is_empty());
    }

    #[test]
    fn hard_hard_active_identity_follows_both_queue_handover_paths() {
        for before_commit in [false, true] {
            let mut ledger = PendingHandshakeState::default();
            let CandidateOfferWorkAdmission::Started(owner, _) =
                ledger.enqueue_candidate_offer_work(offer(1, None))
            else {
                panic!("owner");
            };
            let _ = ledger.enqueue_candidate_offer_work(offer(2, Some("a1")));
            let active = if before_commit {
                ledger.take_queued_candidate_offer_work("private-peer-identity", owner.owner)
            } else {
                ledger.finish_candidate_offer_work("private-peer-identity", owner.owner)
            }
            .unwrap();
            let _ = ledger.enqueue_candidate_offer_work(offer(3, None));
            assert!(matches!(
                ledger.enqueue_candidate_offer_work(offer(4, Some("a1"))),
                CandidateOfferWorkAdmission::Coalesced {
                    reason: HardHardCandidateDiscardReason::SameSessionPreserved,
                    discarded: Some(_),
                }
            ));
            assert!(!ledger.candidate_offer_work_has_priority_successor(
                "private-peer-identity",
                owner.owner,
                &active,
            ));
            let next = ledger
                .finish_candidate_offer_work("private-peer-identity", owner.owner)
                .unwrap();
            assert_eq!(
                next.candidate_generation, 3,
                "duplicate must preserve the queued ordinary refresh"
            );
            assert!(ledger.candidate_offer_workers["private-peer-identity"]
                .active_hard_hard_identity
                .is_none());
        }
    }

    #[test]
    fn hard_hard_same_token_opposite_role_is_not_a_replay() {
        let mut ledger = PendingHandshakeState::default();
        let CandidateOfferWorkAdmission::Started(owner, _) =
            ledger.enqueue_candidate_offer_work(offer(1, Some("a1")))
        else {
            panic!("owner");
        };
        let mut answer = offer(2, Some("a1"));
        let mut coordination =
            HardHardCoordination::parse(answer.session_id.as_deref().unwrap()).unwrap();
        coordination.role = HardHardRole::Responder;
        answer.session_id = Some(coordination.encode());
        assert!(matches!(
            ledger.enqueue_candidate_offer_work(answer),
            CandidateOfferWorkAdmission::Coalesced {
                discarded: None,
                ..
            }
        ));
        assert_eq!(
            ledger
                .finish_candidate_offer_work("private-peer-identity", owner.owner)
                .unwrap()
                .candidate_generation,
            2
        );
    }

    #[test]
    fn hard_hard_priority_rejects_malformed_expired_and_barrier_payloads() {
        let now = hard_hard_now_ms();
        let mut value = offer(1, Some("a1"));
        assert!(hard_hard_candidate_priority(&value, now).is_some());
        value.candidates_expires_at_ms = Some(now);
        assert!(hard_hard_candidate_priority(&value, now).is_none());
        value.candidates_expires_at_ms = None;
        value.session_id = Some("hh1:broken:raw-private-token".to_string());
        assert!(hard_hard_candidate_priority(&value, now).is_none());
        let mut coordination =
            HardHardCoordination::parse(offer(1, Some("a1")).session_id.as_deref().unwrap())
                .unwrap();
        coordination.token = "00112233445566778899aabbccddeeff".to_string();
        coordination.v2 = Some(HardHardV2Envelope {
            stage: HardHardV2Stage::Ready,
            local: crate::peer::HardHardOfferParameters {
                socket_count: 4,
                prediction_count: 2,
                anchor_port: 40_001,
            },
            remote: crate::peer::HardHardOfferParameters {
                socket_count: 4,
                prediction_count: 3,
                anchor_port: 50_001,
            },
            phase: false,
            strategy_order: 0,
            agreement: Some(crate::peer::HardHardAgreedPlan {
                strategy: crate::peer::HardHardProbeStrategy::FixedAnchor,
                digest: [0xa5; 16],
            }),
            rtt_ms: 0,
            uncertainty_ms: 0,
        });
        value.session_id = Some(coordination.encode());
        assert!(HardHardCoordination::parse(value.session_id.as_deref().unwrap()).is_some());
        assert!(hard_hard_candidate_priority(&value, now).is_none());
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<std::sync::Mutex<Vec<HashMap<String, String>>>>);
    #[derive(Default)]
    struct Fields(HashMap<String, String>);
    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() != tracing::Level::INFO {
                return;
            }
            let mut fields = Fields::default();
            event.record(&mut fields);
            if fields
                .0
                .get("event")
                .is_some_and(|value| value.starts_with("hard_hard_"))
            {
                self.0.lock().unwrap().push(fields.0);
            }
        }
    }

    #[tokio::test]
    async fn hard_hard_release_diagnostics_survive_worker_future_drop_without_private_payloads() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://127.0.0.1:1", "diagnostics").unwrap(),
        ));
        assert!(!peers.hard_hard_experiment_only());
        let token = "00112233445566778899aabbccddeeff";
        let value = offer(1, Some(token));
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            hard_hard_a0_stage_log(
                &peers,
                "responder",
                Some(token),
                HardHardA0Stage::PeerSignalReceived,
                HardHardA0Reason::SignalReceived,
            );
            let mut worker = Box::pin(async {
                let _trace = HardHardCandidateTrace::begin(&value, 17, &peers);
                std::future::pending::<()>().await;
            });
            let waker = futures_util::task::noop_waker();
            let mut context = std::task::Context::from_waker(&waker);
            assert!(std::future::Future::poll(worker.as_mut(), &mut context).is_pending());
            drop(worker);
            hard_hard_candidate_discarded(Some(&value), HardHardCandidateDiscardReason::Expired);
            hard_hard_recovery_claim_fence(RecoveryAdmission::BudgetExhausted { epoch: 8 }, 7)
                .unwrap_err()
                .log(
                    Some(token),
                    "responder",
                    crate::peer::HardHardPlanSnapshot {
                        local_network_generation: 4,
                        remote_candidate_epoch: 7,
                        local_profile_generation: 13,
                        remote_profile_generation: 12,
                    },
                    crate::peer::PeerSessionGeneration::for_test(9),
                    7,
                );
        });
        let rows = capture.0.lock().unwrap();
        assert!(rows
            .iter()
            .any(|row| row.get("event").map(String::as_str) == Some("hard_hard_attempt_stage")));
        let terminal = rows
            .iter()
            .filter(|row| {
                row.get("outcome").map(String::as_str) == Some("worker_cancelled_or_dropped")
            })
            .collect::<Vec<_>>();
        assert_eq!(terminal.len(), 1);
        assert_eq!(
            terminal[0]["session_tag"],
            hard_hard_anonymized_tag(token, "session")
        );
        assert!(rows
            .iter()
            .any(|row| row.get("reason_code").map(String::as_str)
                == Some("recovery_budget_exhausted")
                && row["observed_recovery_epoch"] == "Some(8)"));
        let output = format!("{rows:?}");
        for private in [
            token,
            "private-peer-identity",
            "private-public-key",
            "198.51.100.77",
            "45678",
            "raw-private-token",
        ] {
            assert!(!output.contains(private), "private field leaked: {private}");
        }
    }
}
