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
}
