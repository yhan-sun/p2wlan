// A change of authenticated source can request consent on the original path.
// A different receive port by itself neither selects a candidate nor retires Direct.
const REBIND_SOURCE_MAX_AGE: Duration = Duration::from_secs(30);
const REBIND_CHECK_INTERVAL: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Copy)]
struct DirectSourceObservation {
    target: DirectConsentPath,
    source: SocketAddr,
    received: Instant,
    changed_at: Option<Instant>,
    challenge: Option<SocketAddr>,
    owner: Option<u64>,
}

impl PeerConnection {
    fn observe_direct_source(
        &mut self,
        generation: u64,
        lifecycle: Option<PeerSessionGeneration>,
        local: SocketAddr,
        source: SocketAddr,
        received: Instant,
    ) {
        let Some(target) = self.direct_consent_path(generation) else {
            return;
        };
        if lifecycle != Some(target.path.peer_session_generation)
            || target.local_endpoint != Some(local)
            || target.path.endpoint.ip() != source.ip()
            || received.elapsed() > REBIND_SOURCE_MAX_AGE
        {
            return;
        }
        let Some(last) = self.rebind_observation.as_mut() else {
            self.rebind_observation = Some(DirectSourceObservation {
                target,
                source,
                received,
                changed_at: None,
                challenge: None,
                owner: None,
            });
            return;
        };
        if received <= last.received {
            return;
        }
        let fresh = last.target == target
            && received.duration_since(last.received) <= REBIND_SOURCE_MAX_AGE;
        let allowed = last
            .changed_at
            .is_none_or(|at| received.duration_since(at) >= REBIND_CHECK_INTERVAL);
        let changed = fresh && last.source != source && allowed;
        // A commit resets the source baseline, but keeps the rate limit. A
        // stable asymmetric peer naturally receives on a different port.
        if changed {
            last.changed_at = Some(received);
            last.challenge = Some(source);
            last.owner = None;
        } else if !fresh || last.challenge != Some(source) {
            last.challenge = None;
        }
        last.received = received;
        last.target = target;
        last.source = source;
    }

    fn may_validate_alternate(&self, generation: u64, endpoint: SocketAddr) -> bool {
        self.should_upgrade_direct_to_on_link(generation, endpoint)
            || self.rebind_observation.is_some_and(|watch| {
                watch.challenge == Some(endpoint)
                    && watch.owner.is_none_or(|owner| {
                        self.path_state_machine.alternate_validation_owner() == Some(owner)
                    })
                    && watch.target.path.endpoint != endpoint
                    && self.direct_consent_path(generation) == Some(watch.target)
                    && watch
                        .changed_at
                        .is_some_and(|at| at.elapsed() < REBIND_CHECK_INTERVAL)
            })
    }
}
