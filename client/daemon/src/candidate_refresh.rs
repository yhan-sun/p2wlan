use super::*;

include!("candidate_refresh/signals.rs");
include!("candidate_refresh/port_mapping.rs");
include!("candidate_refresh/runtime.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volatile_candidate_churn_is_coalesced_and_not_fanned_out() {
        let mut coalescer = VolatilePublishCoalescer::default();
        let now = Instant::now();
        let churn_a = 0xAAAA_AAAAu64;
        let churn_b = 0xBBBB_BBBBu64;

        // First churn schedules a publish (the only fan-out).
        assert_eq!(
            coalescer.on_churn(churn_a, now),
            VolatileChurnAction::SchedulePublish
        );
        // A same-set churn inside the debounce window is newest-wins merged.
        assert_eq!(
            coalescer.on_churn(churn_a, now + Duration::from_secs(1)),
            VolatileChurnAction::CoalescedNewest
        );
        // A newer set replaces the pending one without an extra schedule.
        assert_eq!(
            coalescer.on_churn(churn_b, now + Duration::from_secs(2)),
            VolatileChurnAction::CoalescedNewest
        );
        // Nothing publishes before the debounce window elapses.  The window
        // slides with each churn (the last one at now+2s), so the earliest
        // due instant is now+32s.
        assert_eq!(coalescer.take_due(now + Duration::from_secs(20)), None);

        // Exactly one publication after the window: the newest set.
        assert_eq!(
            coalescer.take_due(now + Duration::from_secs(33)),
            Some(churn_b)
        );
        coalescer.record_published(churn_b);

        // Churn that oscillates back to the already-published set is fully
        // suppressed, not fanned out again.
        assert_eq!(
            coalescer.on_churn(churn_b, now + Duration::from_secs(40)),
            VolatileChurnAction::SuppressIdentical
        );
        // And no pending publication remains for it.
        assert_eq!(coalescer.take_due(now + Duration::from_secs(80)), None);
    }

    #[test]
    fn canonical_candidate_set_hash_is_order_insensitive_but_sensitive_to_content() {
        let mut sources = HashMap::new();
        sources.insert("1.2.3.4:1000".to_string(), "stun_observed".to_string());
        sources.insert("1.2.3.4:1001".to_string(), "predicted".to_string());
        let a = vec!["1.2.3.4:1000".to_string(), "1.2.3.4:1001".to_string()];
        let b = vec!["1.2.3.4:1001".to_string(), "1.2.3.4:1000".to_string()];
        assert_eq!(
            canonical_candidate_set_hash(&a, &sources),
            canonical_candidate_set_hash(&b, &sources),
            "the canonical hash must be order-insensitive (same set, same hash)"
        );

        // A source promotion changes the canonical content: the deduplicator
        // must warn again instead of swallowing the change.
        let mut promoted = sources.clone();
        promoted.insert("1.2.3.4:1001".to_string(), "peer_reflexive".to_string());
        assert_ne!(
            canonical_candidate_set_hash(&a, &sources),
            canonical_candidate_set_hash(&a, &promoted),
            "a source promotion must change the canonical hash"
        );

        // A different truncated set is different canonical content.
        let mut truncated = a.clone();
        truncated.pop();
        assert_ne!(
            canonical_candidate_set_hash(&a, &sources),
            canonical_candidate_set_hash(&truncated, &sources),
            "a different truncated set must change the canonical hash"
        );
    }

    #[test]
    fn truncation_reporter_deduplicates_identical_canonical_content() {
        // The same over-limit set refreshing repeatedly must warn exactly once
        // per canonical content and stay observable as a counter, never a
        // log flood (the 98→96-refresh-every-cycle case).
        let mut reporter = TruncationReporter::default();
        let hash_a = 42u64;
        assert!(
            reporter.report(hash_a),
            "the first truncation of a canonical content must warn"
        );
        assert!(
            !reporter.report(hash_a),
            "identical content must stay silent"
        );
        assert!(!reporter.report(hash_a), "identical content stays silent");
        let (total, identical) = reporter.counters();
        assert_eq!(total, 3);
        assert_eq!(identical, 2);

        assert!(
            reporter.report(43u64),
            "new canonical content must warn again"
        );
        let (total, identical) = reporter.counters();
        assert_eq!(total, 4);
        assert_eq!(identical, 2, "only the second content's repeats are silent");
    }

    #[test]
    fn public_candidate_readiness_transition_bypasses_volatile_debounce() {
        let host = vec!["192.168.0.239:52268".to_string()];
        let host_sources = HashMap::from([(host[0].clone(), "host".to_string())]);
        let public = vec![host[0].clone(), "8.8.8.8:41000".to_string()];
        let public_sources = HashMap::from([
            (host[0].clone(), "host".to_string()),
            ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
        ]);

        assert!(public_candidate_readiness_changed(
            &host,
            &host_sources,
            &public,
            &public_sources,
        ));
        assert!(public_candidate_readiness_changed(
            &public,
            &public_sources,
            &host,
            &host_sources,
        ));
    }

    #[test]
    fn public_port_churn_and_predicted_ports_do_not_trigger_readiness_transition() {
        let previous = vec!["8.8.8.8:41000".to_string()];
        let previous_sources = HashMap::from([(previous[0].clone(), "stun_observed".to_string())]);
        let next = vec!["8.8.8.8:41001".to_string()];
        let next_sources = HashMap::from([(next[0].clone(), "stun_observed".to_string())]);
        assert!(!public_candidate_readiness_changed(
            &previous,
            &previous_sources,
            &next,
            &next_sources,
        ));

        let predicted = vec!["8.8.8.8:41002".to_string()];
        let predicted_sources = HashMap::from([(predicted[0].clone(), "predicted".to_string())]);
        assert!(!has_real_public_candidate(&predicted, &predicted_sources));
        assert!(public_candidate_readiness_changed(
            &previous,
            &previous_sources,
            &predicted,
            &predicted_sources,
        ));
    }
}
