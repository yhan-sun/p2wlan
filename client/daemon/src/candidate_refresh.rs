use super::*;

include!("candidate_refresh/signals.rs");
include!("candidate_refresh/port_mapping.rs");
include!("candidate_refresh/gather_fence.rs");
include!("candidate_refresh/runtime.rs");

#[cfg(test)]
mod tests {
    use super::*;

    include!("candidate_refresh/gather_fence_tests.rs");
    include!("candidate_refresh/periodic_commit_tests.rs");

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
        // The deadline is fixed from the first churn.  A later churn must not
        // slide it indefinitely, otherwise a busy NAT can starve the peer of
        // its newest public endpoint.
        assert_eq!(coalescer.take_due(now + Duration::from_millis(499)), None);

        // Exactly one publication after the window: the newest set.
        assert_eq!(
            coalescer.take_due(now + Duration::from_millis(500)),
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
    fn volatile_candidate_return_to_published_set_retracts_pending_change() {
        let now = Instant::now();
        let mut coalescer = VolatilePublishCoalescer::default();
        coalescer.record_published(1);
        assert_eq!(
            coalescer.on_churn(2, now),
            VolatileChurnAction::SchedulePublish
        );
        assert_eq!(
            coalescer.on_churn(1, now + Duration::from_millis(100)),
            VolatileChurnAction::SuppressIdentical
        );
        assert_eq!(coalescer.pending_deadline(), None);
        assert_eq!(coalescer.take_due(now + Duration::from_millis(500)), None);

        // A later real change receives a fresh, bounded debounce window.
        let next = now + Duration::from_millis(600);
        assert_eq!(
            coalescer.on_churn(3, next),
            VolatileChurnAction::SchedulePublish
        );
        assert_eq!(coalescer.take_due(next + Duration::from_millis(499)), None);
        assert_eq!(
            coalescer.take_due(next + Duration::from_millis(500)),
            Some(3)
        );
        assert_eq!(coalescer.take_due(next + Duration::from_secs(1)), None);
    }

    #[test]
    fn refresh_c1_periodic_wake_starts_one_full_gather() {
        let wake = refresh_wake_reason(true, false).expect("periodic wake");
        assert_eq!(wake, RefreshWakeReason::Periodic);
        assert!(wake.permits_full_gather());
    }

    #[test]
    fn refresh_c2_volatile_deadline_publishes_without_full_gather() {
        let wake = refresh_wake_reason(false, true).expect("volatile wake");
        assert_eq!(wake, RefreshWakeReason::VolatileDeadline);
        assert!(!wake.permits_full_gather());

        let now = Instant::now();
        let mut coalescer = VolatilePublishCoalescer::default();
        assert_eq!(
            coalescer.on_churn(1, now),
            VolatileChurnAction::SchedulePublish
        );
        assert_eq!(
            coalescer.take_due(now + Duration::from_millis(500)),
            Some(1)
        );
    }

    #[test]
    fn refresh_c3_continuous_volatile_changes_coalesce_to_one_publish() {
        let now = Instant::now();
        let mut coalescer = VolatilePublishCoalescer::default();
        let mut scheduled = 0;
        let mut coalesced = 0;
        for (offset_ms, hash) in [10u64, 20, 30, 40, 50].into_iter().enumerate() {
            let action = coalescer.on_churn(hash, now + Duration::from_millis(offset_ms as u64));
            match action {
                VolatileChurnAction::SchedulePublish => scheduled += 1,
                VolatileChurnAction::CoalescedNewest => coalesced += 1,
                VolatileChurnAction::SuppressIdentical => {}
            }
        }
        assert_eq!(scheduled, 1);
        assert_eq!(coalesced, 4);
        assert_eq!(
            coalescer.take_due(now + Duration::from_millis(510)),
            Some(50)
        );
        assert_eq!(coalescer.take_due(now + Duration::from_secs(1)), None);
    }

    #[test]
    fn refresh_c4_simultaneous_periodic_and_volatile_wake_keeps_periodic_gather() {
        let wake = refresh_wake_reason(true, true).expect("simultaneous wake");
        assert_eq!(wake, RefreshWakeReason::Periodic);
        assert!(wake.permits_full_gather());
    }

    #[test]
    fn refresh_c5_sixty_seconds_has_only_periodic_full_gathers() {
        let start = Instant::now();
        let volatile_changes = [1u64, 5, 16, 30, 45, 59];
        let mut coalescer = VolatilePublishCoalescer::default();
        let mut full_gathers = 0;
        let mut volatile_publishes = 0;

        // The production worker consumes the immediate interval tick during
        // startup. This fake-clock run therefore models periodic gathers at
        // 15, 30, 45, and 60 seconds, while volatile deadlines are serviced
        // independently between them.
        for second in 0..=60u64 {
            let now = start + Duration::from_secs(second);
            if volatile_changes.contains(&second) {
                coalescer.on_churn(second, now);
            }
            let periodic_ready = second > 0 && second % 15 == 0;
            let volatile_ready = coalescer.pending_due(now);
            let Some(wake) = refresh_wake_reason(periodic_ready, volatile_ready) else {
                continue;
            };

            if volatile_ready {
                assert!(
                    coalescer.take_due(now).is_some(),
                    "a ready volatile deadline must be consumed"
                );
                volatile_publishes += 1;
            }
            if wake.permits_full_gather() {
                full_gathers += 1;
            }
        }

        assert_eq!(
            full_gathers, 4,
            "only the 15-second periodic cadence gathers"
        );
        assert_eq!(volatile_publishes, volatile_changes.len());
        assert!(
            full_gathers <= 5,
            "60-second run must not become a gather storm"
        );
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

    #[test]
    fn mapping_dependent_socket_pool_gets_one_fast_post_bind_refresh() {
        let mut profile = p2pnet_nat::NatProfile {
            local_addr: "192.168.0.239:59270".to_string(),
            observations: Vec::new(),
            udp_blocked: false,
            public_endpoint: Some("220.163.6.190:4872".to_string()),
            public_ip_stable: Some(true),
            public_port_stable: Some(false),
            port_preserved: Some(false),
            port_delta: Some(1),
            likely_symmetric: Some(true),
            mapping_behavior: p2pnet_nat::MappingBehavior::AddressOrPortDependent,
            filtering_behavior: p2pnet_nat::FilteringBehavior::Unknown,
            hairpin_behavior: p2pnet_nat::HairpinBehavior::Unknown,
            mapping_lifetime: p2pnet_nat::MappingLifetime::Unknown,
            prediction_candidate: true,
            predicted_endpoints: Vec::new(),
            birthday_candidate: true,
            confidence: 60,
        };

        assert!(should_warm_mapping_dependent_socket_pool(
            3,
            true,
            Some(&profile)
        ));
        assert!(!should_warm_mapping_dependent_socket_pool(
            1,
            true,
            Some(&profile)
        ));
        assert!(!should_warm_mapping_dependent_socket_pool(
            3,
            false,
            Some(&profile)
        ));

        profile.mapping_behavior = p2pnet_nat::MappingBehavior::EndpointIndependent;
        assert!(!should_warm_mapping_dependent_socket_pool(
            3,
            true,
            Some(&profile)
        ));
    }

    #[test]
    fn pool_public_candidate_does_not_end_startup_retry_when_primary_mapping_is_blocked() {
        let candidates = vec!["220.163.6.190:62943".to_string()];
        let sources = HashMap::from([(candidates[0].clone(), "stun_observed".to_string())]);
        let mut profile = p2pnet_nat::NatProfile {
            local_addr: "192.168.0.239:59270".to_string(),
            observations: Vec::new(),
            udp_blocked: true,
            public_endpoint: None,
            public_ip_stable: None,
            public_port_stable: None,
            port_preserved: None,
            port_delta: None,
            likely_symmetric: None,
            mapping_behavior: p2pnet_nat::MappingBehavior::UdpBlocked,
            filtering_behavior: p2pnet_nat::FilteringBehavior::UdpBlocked,
            hairpin_behavior: p2pnet_nat::HairpinBehavior::Unknown,
            mapping_lifetime: p2pnet_nat::MappingLifetime::Unknown,
            prediction_candidate: false,
            predicted_endpoints: Vec::new(),
            birthday_candidate: false,
            confidence: 60,
        };

        assert!(has_real_public_candidate(&candidates, &sources));
        assert!(!has_reliable_public_candidate(
            Some(&profile),
            &candidates,
            &sources,
        ));

        profile.udp_blocked = false;
        profile.public_endpoint = Some("8.8.8.8:41000".to_string());
        assert!(!has_reliable_public_candidate(
            Some(&profile),
            &candidates,
            &sources,
        ));

        let primary = profile.public_endpoint.clone().unwrap();
        let mut candidates = candidates;
        candidates.push(primary.clone());
        let mut sources = sources;
        sources.insert(primary, "stun_observed".to_string());
        assert!(has_reliable_public_candidate(
            Some(&profile),
            &candidates,
            &sources,
        ));
    }

    #[test]
    fn test_port_mapping_local_addr_wildcard_resolution() {
        let wildcard: SocketAddr = "0.0.0.0:61302".parse().unwrap();
        let mut sources = HashMap::new();
        let host_cand = "192.168.1.100:61302".to_string();
        sources.insert(host_cand.clone(), "host".to_string());

        // 1. When host candidate is in the list, resolves host candidate
        let resolved = port_mapping_local_addr(
            Some(wildcard),
            std::slice::from_ref(&host_cand),
            &sources,
            None,
        );
        assert_eq!(resolved, Some("192.168.1.100:61302".parse().unwrap()));

        // 1b. Stale host candidate port from previous socket is rebound to current socket port
        let stale_host = "192.168.1.100:54321".to_string();
        let mut stale_sources = HashMap::new();
        stale_sources.insert(stale_host.clone(), "host".to_string());
        let resolved_stale =
            port_mapping_local_addr(Some(wildcard), &[stale_host], &stale_sources, None);
        assert_eq!(
            resolved_stale,
            Some("192.168.1.100:61302".parse().unwrap()),
            "Must bind to current UDP socket port, not stale candidate port"
        );

        // 2. Multi-NIC interface selection: selects the interface matching the default gateway subnet
        let mock_addresses = vec![
            IpAddr::V4("10.0.0.5".parse().unwrap()),
            IpAddr::V4("192.168.1.100".parse().unwrap()),
        ];
        let gw_192 = Some("192.168.1.1".parse::<Ipv4Addr>().unwrap());
        let gw_10 = Some("10.0.0.1".parse::<Ipv4Addr>().unwrap());

        let resolved_gw_192 = port_mapping_local_addr_with_addresses(
            Some(wildcard),
            &[],
            &HashMap::new(),
            gw_192,
            &mock_addresses,
        );
        assert_eq!(
            resolved_gw_192,
            Some("192.168.1.100:61302".parse().unwrap()),
            "Must choose 192.168.1.100 matching gateway 192.168.1.1 subnet"
        );

        let resolved_gw_10 = port_mapping_local_addr_with_addresses(
            Some(wildcard),
            &[],
            &HashMap::new(),
            gw_10,
            &mock_addresses,
        );
        assert_eq!(
            resolved_gw_10,
            Some("10.0.0.5:61302".parse().unwrap()),
            "Must choose 10.0.0.5 matching gateway 10.0.0.1 subnet"
        );

        // A prior host snapshot can put the secondary interface first.  For a
        // wildcard-bound socket, gateway mapping must still use the interface
        // that reaches the selected default gateway.
        let wrong_interface_host = "10.0.0.5:61302".to_string();
        let gateway_interface_host = "192.168.1.100:61302".to_string();
        let host_sources = HashMap::from([
            (wrong_interface_host.clone(), "host".to_string()),
            (gateway_interface_host.clone(), "host".to_string()),
        ]);
        let host_selected_gateway_192 = port_mapping_local_addr_with_addresses(
            Some(wildcard),
            &[wrong_interface_host, gateway_interface_host],
            &host_sources,
            gw_192,
            &mock_addresses,
        );
        assert_eq!(
            host_selected_gateway_192,
            Some("192.168.1.100:61302".parse().unwrap()),
            "Host-candidate order must not override the gateway interface"
        );

        // 3. Direct LAN IP on socket is preserved
        let direct_lan: SocketAddr = "192.168.1.50:51820".parse().unwrap();
        assert_eq!(
            port_mapping_local_addr(Some(direct_lan), &[], &HashMap::new(), None),
            Some(direct_lan)
        );

        // 4. Loopback or port 0 is rejected
        let loopback: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        assert_ne!(
            port_mapping_local_addr(Some(loopback), &[], &HashMap::new(), None),
            Some(loopback)
        );
        let port_zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert_eq!(
            port_mapping_local_addr(Some(port_zero), &[], &HashMap::new(), None),
            None
        );
    }

    #[test]
    fn test_stale_gateway_mapping_rejected_on_socket_or_generation_change() {
        let initial_udp: Option<SocketAddr> = Some("0.0.0.0:40001".parse().unwrap());
        let rebound_udp: Option<SocketAddr> = Some("0.0.0.0:40002".parse().unwrap());
        let initial_gen = 1u64;
        let advanced_gen = 2u64;

        assert!(
            !port_mapping_result_is_current(initial_udp, initial_gen, rebound_udp, initial_gen),
            "Socket rebound must mark mapping stale"
        );
        assert!(
            !port_mapping_result_is_current(initial_udp, initial_gen, initial_udp, advanced_gen),
            "Generation advance must mark mapping stale"
        );
        assert!(
            port_mapping_result_is_current(initial_udp, initial_gen, initial_udp, initial_gen),
            "Matching socket and generation is valid"
        );
    }
}
