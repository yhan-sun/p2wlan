//! Measurement evidence shared by the versioned Hard/Hard plan selector.
//! Socket ownership remains in the existing provisional-socket guards.

use super::*;
use p2pnet_nat::mapping::allocation::validate_allocation_prediction_tail;
use p2pnet_nat::{
    infer_port_domain, infer_scoped_allocation, plan_fixed_anchor, validate_allocation_attempts,
    AllocationAttempt, AllocationEvidenceRejection, AllocationIdentity, AllocationSample,
    FixedAnchorPlan, PortDomainEvidence, ScopedAllocationEvidence,
};

pub(crate) struct HardHardPreparedMeasurement {
    /// Owns every exact socket/guard, including the predictable first socket.
    pub(crate) birthday: HardHardBirthdayResult,
    pub(crate) identity: AllocationIdentity,
    /// Complete bounded syscall ledger. A timeout remains SentUnobserved;
    /// successful observation counts alone cannot establish consumption.
    pub(crate) measurement_trace: Vec<AllocationAttempt>,
    /// Immutable observations reconciled against that same bounded ledger.
    pub(super) measurement_samples: Vec<AllocationSample>,
    pub(crate) allocation: Option<ScopedAllocationEvidence>,
    pub(crate) allocation_rejection: Option<AllocationEvidenceRejection>,
    /// Evidence-only view of the first owned socket; it owns no second guard.
    pub(crate) predictable: Option<FreshMappingResult>,
    /// Original monotonic schedule and its upper forecast bound. Rechecking
    /// publication never advances either value or the actual sample times.
    pub(super) scheduled_send: Option<(u64, u64)>,
}

/// Only an independently rebuilt primary tail may use its later sample time
/// for freshness. The original batch-to-send forecast bound is still checked:
/// rebasing evidence cannot extend the scheduled send or its allowed horizon.
fn validate_prepared_publication_timing(
    batch_started_at_ms: u64,
    independent_prediction_sampled_at_ms: Option<u64>,
    now_ms: u64,
    scheduled_send: (u64, u64),
) -> std::result::Result<(), AllocationEvidenceRejection> {
    use AllocationEvidenceRejection as Reject;
    if batch_started_at_ms > now_ms {
        return Err(Reject::Stale);
    }
    let sampled_at_ms = independent_prediction_sampled_at_ms.unwrap_or(batch_started_at_ms);
    if sampled_at_ms < batch_started_at_ms {
        return Err(Reject::InconsistentOrder);
    }
    let (send_at_ms, horizon_ms) = scheduled_send;
    p2pnet_nat::mapping::allocation::validate_allocation_publication_timing(
        sampled_at_ms,
        now_ms,
        send_at_ms,
        FRESH_MAPPING_MODEL_MAX_AGE,
        Duration::from_millis(horizon_ms),
    )?;
    if send_at_ms.saturating_sub(batch_started_at_ms) > horizon_ms {
        return Err(Reject::ForecastHorizonExceeded);
    }
    Ok(())
}

impl HardHardPreparedMeasurement {
    /// Strategy preference only: a regular verified primary tail retains the cheap
    /// primary-socket attempt. It does not establish an allocator scope or
    /// promise that other clients will remain quiet after the measurement.
    pub(crate) fn prefers_narrow_prediction(&self) -> bool {
        regular_allocation_measurement(&self.measurement_samples, &self.measurement_trace)
    }

    pub(crate) fn measurement_cost(&self) -> HardHardMeasurementStats {
        self.birthday.measurement
    }

    /// Call immediately before publishing the immutable offer. Unknown final
    /// STUN allocations may still use birthday guessing, but never advertise
    /// prediction/anchor evidence. This is not a physical-send identity fence.
    pub(crate) fn validate_publication(
        &self,
        network_generation: u64,
        prediction_count: usize,
        anchor_port: u16,
    ) -> std::result::Result<(), AllocationEvidenceRejection> {
        use AllocationEvidenceRejection as Reject;
        let primary = self
            .birthday
            .sockets
            .first()
            .ok_or(Reject::IdentityChanged)?;
        if network_generation != self.identity.network_generation
            || primary.punch_generation != self.identity.measurement_generation
        {
            return Err(Reject::IdentityChanged);
        }
        let batch_started_at_ms = self
            .birthday
            .measurement
            .measurement_started_at_ms
            .ok_or(Reject::SampleCount)?;
        let scheduled_send = self.scheduled_send.ok_or(Reject::ForecastExpired)?;
        if prediction_count > 0 {
            let candidates = self.prediction_candidates(network_generation, prediction_count)?;
            if prediction_count > 32 || candidates.len() != prediction_count {
                return Err(Reject::NoConsistentStep);
            }
        }
        // prediction_candidates reconciles this exact immutable tail with all
        // sends before its sample time can be used. A model built with Some
        // allocation may borrow the full grid's step/domain, even when this
        // particular offer omits its anchor; it retains the earlier age limit.
        let independent_prediction_sampled_at_ms = self
            .predictable
            .as_ref()
            .filter(|_| prediction_count > 0 && anchor_port == 0 && self.allocation.is_none())
            .map(|prediction| prediction.model.sampled_at_ms);
        validate_prepared_publication_timing(
            batch_started_at_ms,
            independent_prediction_sampled_at_ms,
            monotonic_millis(),
            scheduled_send,
        )?;
        if anchor_port != 0 {
            let count = self.birthday.sockets.len();
            let anchor =
                self.fixed_anchor_plan(network_generation, count, count.saturating_sub(1))?;
            if anchor.local_anchor.port() != anchor_port {
                return Err(Reject::IdentityChanged);
            }
        }
        Ok(())
    }

    fn validate_plan_identity(
        &self,
        network_generation: u64,
    ) -> std::result::Result<(), AllocationEvidenceRejection> {
        use AllocationEvidenceRejection as Reject;
        let Some(primary) = self.birthday.sockets.first() else {
            return Err(Reject::IdentityChanged);
        };
        if network_generation != self.identity.network_generation
            || primary.punch_generation != self.identity.measurement_generation
        {
            return Err(Reject::IdentityChanged);
        }
        Ok(())
    }

    /// Revalidate the evidence when publishing/agreeing a plan. Physical sends
    /// still require the existing exact session/socket/profile fences.
    pub(crate) fn prediction_candidates(
        &self,
        network_generation: u64,
        cap: usize,
    ) -> std::result::Result<Vec<SocketAddr>, AllocationEvidenceRejection> {
        self.validate_plan_identity(network_generation)?;
        let prediction = self
            .predictable
            .as_ref()
            .ok_or(AllocationEvidenceRejection::NoConsistentStep)?;
        let primary = &self.birthday.sockets[0]; // validate_plan_identity checked it.
        let tail = validate_allocation_prediction_tail(
            &self.measurement_samples,
            &self.measurement_trace,
            primary.socket_index,
            primary.socket_local_endpoint,
        )?;
        if prediction.network_generation != network_generation
            || prediction.punch_generation != primary.punch_generation
            || prediction.socket_index != primary.socket_index
            || prediction.socket_local_endpoint != primary.socket_local_endpoint
            || prediction.model.sampled_at_ms != tail[0].observation.sent_at_ms
            || prediction.model.sequence
                != tail
                    .iter()
                    .map(|sample| sample.observation.observed.port())
                    .collect::<Vec<_>>()
            || prediction.public_ip != Some(self.birthday.public_ip)
            || prediction.model.public_ip != Some(self.birthday.public_ip)
        {
            return Err(AllocationEvidenceRejection::IdentityChanged);
        }
        if !p2pnet_nat::model_is_fresh(
            &prediction.model,
            FRESH_MAPPING_MODEL_MAX_AGE,
            monotonic_millis(),
        ) {
            return Err(AllocationEvidenceRejection::Stale);
        }
        let ports = p2pnet_nat::mapping::rendezvous::bounded_prediction_window(
            &prediction.predicted_ports,
            cap.min(32),
        );
        if ports.is_empty() {
            return Err(AllocationEvidenceRejection::NoConsistentStep);
        }
        Ok(ports
            .into_iter()
            .map(|port| SocketAddr::new(self.birthday.public_ip, port))
            .collect())
    }

    /// Candidate guesses for the existing birthday lane. This deliberately
    /// grants no predictable prefix or shared-allocator/anchor authority.
    pub(crate) fn contention_candidates(
        &self,
        network_generation: u64,
        cap: usize,
    ) -> std::result::Result<Vec<SocketAddr>, AllocationEvidenceRejection> {
        self.prediction_candidates(network_generation, 1)?;
        let prediction = self
            .predictable
            .as_ref()
            .ok_or(AllocationEvidenceRejection::NoConsistentStep)?;
        Ok(
            p2pnet_nat::mapping::rendezvous::contention_candidate_window(&prediction.model, cap)
                .into_iter()
                .map(|port| SocketAddr::new(self.birthday.public_ip, port))
                .collect(),
        )
    }

    /// A bounded conditional attempt. Prefix consumption is before the first
    /// socket sends, not an allowance for arbitrary interleaved allocations.
    pub(crate) fn fixed_anchor_plan(
        &self,
        network_generation: u64,
        socket_count: usize,
        max_prefix_allocations: usize,
    ) -> std::result::Result<FixedAnchorPlan, AllocationEvidenceRejection> {
        self.validate_plan_identity(network_generation)?;
        validate_allocation_attempts(&self.measurement_samples, &self.measurement_trace)?;
        if socket_count > self.birthday.sockets.len() {
            return Err(AllocationEvidenceRejection::InvalidSocketCount);
        }
        let evidence = self.allocation.as_ref().ok_or_else(|| {
            self.allocation_rejection
                .unwrap_or(AllocationEvidenceRejection::ScopeUnproven)
        })?;
        plan_fixed_anchor(
            evidence,
            self.identity,
            monotonic_millis(),
            FRESH_MAPPING_MODEL_MAX_AGE,
            socket_count,
            max_prefix_allocations,
        )
    }
}

fn regular_allocation_measurement(
    samples: &[AllocationSample],
    attempts: &[AllocationAttempt],
) -> bool {
    let Some(last) = samples.last() else {
        return false;
    };
    let Ok(tail) = validate_allocation_prediction_tail(
        samples,
        attempts,
        last.socket_id,
        last.observation.local_endpoint,
    ) else {
        return false;
    };
    // Different sockets may have different allocators. Their gaps are not
    // proof of contention on this validated primary socket.
    infer_port_domain(
        &tail
            .iter()
            .map(|sample| sample.observation.observed.port())
            .collect::<Vec<_>>(),
    )
    .is_ok()
}

/// Choose measurement destinations, never mapping evidence. Prefer a complete
/// primary tail over a four-observer grid with a known-unresponsive endpoint.
/// Cold/incomplete gathers retain configured observers so stale hints cannot
/// prevent a new measurement. Every selected endpoint is measured again.
fn select_measurement_observers(
    configured: &[SocketAddr],
    hints: &[p2pnet_nat::StunObservation],
) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut ranked = configured
        .iter()
        .copied()
        .filter(|addr| addr.is_ipv4() && seen.insert(*addr))
        .map(|addr| {
            let hint = hints
                .iter()
                .find(|hint| hint.server.parse::<SocketAddr>().ok() == Some(addr));
            let rank = match hint {
                Some(hint) if hint.mapped_address.is_some() && hint.error.is_none() => 0,
                None => 1,
                Some(_) => 2,
            };
            (
                addr,
                rank,
                hint.and_then(|hint| hint.rtt_ms).unwrap_or(u64::MAX),
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by_key(|(_, rank, rtt)| (*rank, *rtt));
    let responsive = ranked.iter().take_while(|(_, rank, _)| *rank == 0).count();
    if responsive >= 3 {
        ranked.truncate(responsive);
    }
    // Cross-address observations help prove allocator scope in a complete
    // grid. A three-observer primary tail needs no secondary-socket ordering.
    if ranked.len() >= 4 {
        let first_ip = ranked[0].0.ip();
        if let Some(other) = ranked.iter().position(|(addr, ..)| addr.ip() != first_ip) {
            ranked.swap(1, other);
        }
    }
    ranked.into_iter().take(4).map(|(addr, ..)| addr).collect()
}

pub(super) struct HardHardGridMeasurement {
    pub(super) observations_by_socket: Vec<Vec<MappingObservation>>,
    pub(super) samples: Vec<AllocationSample>,
    pub(super) attempts: Vec<AllocationAttempt>,
    pub(super) stats: HardHardMeasurementStats,
}

impl UdpTransport {
    pub(super) async fn measure_hard_hard_grid(
        &self,
        sockets: &[(usize, Arc<UdpSocket>)],
        observers: &[SocketAddr],
        stun_timeout: Duration,
        keep_measuring: impl Fn() -> bool,
    ) -> HardHardGridMeasurement {
        let hints = self.peers.local_stun_observation_hints().await;
        let selected = select_measurement_observers(observers, &hints);
        let mut pairs = Vec::new();
        if sockets.len() >= 2 && selected.len() >= 4 {
            // The last grid send is A1. A2/A3 then extend that same socket's
            // ordered tail without another socket consuming an allocation.
            pairs.extend([(0, 0), (1, 0), (1, 1), (0, 1), (0, 2), (0, 3)]);
        } else if !sockets.is_empty() {
            pairs.extend((0..selected.len()).map(|observer| (0, observer)));
        }
        let requests = pairs
            .iter()
            .map(|(socket, observer)| (sockets[*socket].1.clone(), selected[*observer]))
            .collect::<Vec<_>>();
        info!(
            event = "hard_hard_measurement_plan",
            configured_observer_count = observers.len(),
            selected_observer_count = selected.len(),
            measurement_request_count = requests.len(),
            measurement_budget_ms = FRESH_MAPPING_MEASURE_BUDGET.as_millis() as u64,
            "Prepared bounded fresh STUN measurement"
        );
        let measurement = self
            .measure_ordered_mapping_requests_with_primary_fallback(
                &requests,
                (pairs.len() == 6).then(|| &sockets[0].1),
                stun_timeout,
                keep_measuring,
            )
            .await;
        let mut observations_by_socket = vec![Vec::new(); sockets.len()];
        let mut samples = Vec::new();
        for observation in measurement.observations {
            // The collector may replace the remaining grid with a primary
            // tail. Attribute actual observations by the bound local socket,
            // never by the original request's now-obsolete sequence position.
            let Some(position) = sockets.iter().position(|(_, socket)| {
                socket.local_addr().ok() == Some(observation.local_endpoint)
            }) else {
                continue;
            };
            observations_by_socket[position].push(observation.clone());
            samples.push(AllocationSample {
                socket_id: sockets[position].0,
                observation,
            });
        }
        HardHardGridMeasurement {
            observations_by_socket,
            samples,
            attempts: measurement.attempts,
            stats: measurement.stats,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepared_prediction(
    samples: &[AllocationSample],
    attempts: &[AllocationAttempt],
    identity: AllocationIdentity,
    socket_index: usize,
    socket_local_endpoint: SocketAddr,
    measurement: HardHardMeasurementStats,
    scheduled_send: (u64, u64),
    now_ms: u64,
) -> (
    Option<ScopedAllocationEvidence>,
    Option<AllocationEvidenceRejection>,
    Option<FreshMappingResult>,
) {
    // Shared-allocator evidence still requires every attempted send. A later
    // complete primary tail may rebase its own predictor after an unknown
    // early allocation, but cannot repair the incomplete cross-socket grid.
    let allocation_result = validate_allocation_attempts(samples, attempts).and_then(|()| {
        infer_scoped_allocation(samples, identity, now_ms, FRESH_MAPPING_MODEL_MAX_AGE)
    });
    let allocation_rejection = allocation_result.as_ref().err().copied();
    let allocation = allocation_result.ok();
    let delay_ms = scheduled_send.0.saturating_sub(now_ms);
    if delay_ms > scheduled_send.1 {
        return (allocation, allocation_rejection, None);
    }
    // No guessed consumption count: the first observation of this complete
    // suffix is the new base, and the ledger proves there was no unobserved
    // send or other socket's allocation after that suffix.
    let Ok(samples) =
        validate_allocation_prediction_tail(samples, attempts, socket_index, socket_local_endpoint)
    else {
        return (allocation, allocation_rejection, None);
    };
    let tail = samples
        .iter()
        .map(|sample| &sample.observation)
        .collect::<Vec<_>>();
    let Some(first) = tail.first() else {
        return (allocation, allocation_rejection, None);
    };
    let Some(last) = tail.last() else {
        return (allocation, allocation_rejection, None);
    };
    if tail.iter().any(|sample| sample.responded_at_ms > now_ms)
        || first.sent_at_ms > now_ms
        || now_ms.saturating_sub(first.sent_at_ms) > FRESH_MAPPING_MODEL_MAX_AGE.as_millis() as u64
    {
        return (allocation, allocation_rejection, None);
    }
    let sequence = tail
        .iter()
        .map(|sample| sample.observed.port())
        .collect::<Vec<_>>();
    let mut model = p2pnet_nat::build_model(&sequence, Some(first.observed.ip()), first.sent_at_ms);
    let domain = match allocation.as_ref() {
        Some(evidence) => {
            // The complete grid can identify a wrap that the short tail alone
            // cannot distinguish. Its last sample is also this primary tail.
            model.kind = PortModelKind::FixedStep {
                step: evidence.step,
            };
            model.deltas = vec![evidence.step; sequence.len() - 1];
            model.confidence = 90;
            evidence.domain
        }
        None => infer_port_domain(&sequence)
            .map(|(_, domain)| domain)
            .unwrap_or(PortDomainEvidence::Unobserved),
    };
    let bounded_step = match &model.kind {
        PortModelKind::FixedStep { step }
        | PortModelKind::Linear { step }
        | PortModelKind::NoisyLinear { step } => {
            step.unsigned_abs() <= FRESH_MAPPING_MAX_ABS_STEP as u16
        }
        _ => true,
    };
    if !bounded_step {
        return (allocation, allocation_rejection, None);
    }
    let predicted_ports = if let PortModelKind::FixedStep { step } = model.kind {
        (1..=p2pnet_nat::MAX_PREDICTED_PORTS)
            .map_while(|distance| {
                domain.advance(last.observed.port(), i64::from(step) * distance as i64)
            })
            .collect()
    } else if model.kind.clone().is_predictable() {
        let timing = p2pnet_nat::mapping::rendezvous::RendezvousPredictionTiming {
            measurement_span_ms: last.sent_at_ms.saturating_sub(first.sent_at_ms),
            last_measurement_send_at_ms: last.sent_at_ms,
            now_ms,
            send_delay_ms: delay_ms,
            max_send_delay_ms: scheduled_send.1,
            max_model_age: FRESH_MAPPING_MODEL_MAX_AGE,
        };
        p2pnet_nat::mapping::rendezvous::predict_for_rendezvous(
            &model,
            last.observed.port(),
            timing,
            None,
            false,
        )
        .unwrap_or_default()
        .into_iter()
        .filter(|candidate| {
            // With no domain evidence, never manufacture a wrap from the
            // legacy 16-bit arithmetic used by hh1's hypothesis generator.
            let delta = i32::from(candidate.port) - i32::from(last.observed.port());
            model
                .deltas
                .iter()
                .all(|step| *step == 0 || delta.signum() == i32::from(*step).signum())
        })
        .map(|candidate| candidate.port)
        .collect()
    } else {
        Vec::new()
    };
    let prediction = (!predicted_ports.is_empty()).then_some(FreshMappingResult {
        punch_generation: identity.measurement_generation,
        network_generation: identity.network_generation,
        socket_local_endpoint,
        socket_index,
        model,
        predicted_ports,
        public_ip: Some(first.observed.ip()),
        first_punch_sent_at_ms: 0,
        last_punch_sent_at_ms: 0,
        measurement,
    });
    (allocation, allocation_rejection, prediction)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2pnet_nat::AllocationAttemptOutcome as Outcome;

    #[test]
    fn observer_hints_preserve_a_complete_fast_to_slow_primary_tail() {
        let configured = (1..=5)
            .map(|host| format!("203.0.113.{host}:3478").parse().unwrap())
            .collect::<Vec<SocketAddr>>();
        let hints = configured
            .iter()
            .zip([None, Some(450), None, Some(30), Some(20)])
            .map(|(addr, rtt)| p2pnet_nat::StunObservation {
                server: addr.to_string(),
                mapped_address: rtt.map(|_| "198.51.100.1:40000".into()),
                rtt_ms: rtt,
                error: rtt.is_none().then(|| "timeout".into()),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            select_measurement_observers(&configured, &hints),
            [configured[4], configured[3], configured[1]],
            "a slow third primary sample need not move into the grid's second position"
        );
    }

    #[test]
    fn cold_or_incomplete_observer_hints_keep_configured_fallbacks() {
        let configured = (1..=5)
            .map(|host| format!("203.0.113.{host}:3478").parse().unwrap())
            .collect::<Vec<SocketAddr>>();
        assert_eq!(
            select_measurement_observers(&configured, &[]),
            configured[..4]
        );
        let hint = p2pnet_nat::StunObservation {
            server: configured[0].to_string(),
            mapped_address: None,
            rtt_ms: None,
            error: Some("old timeout".into()),
        };
        assert_eq!(
            select_measurement_observers(&configured, &[hint]),
            configured[1..],
            "unknown configured destinations must remain eligible for live measurement"
        );
    }

    #[test]
    fn observer_hints_cannot_add_endpoints_or_duplicate_measurements() {
        let a = "203.0.113.1:3478".parse().unwrap();
        let b = "203.0.113.2:3478".parse().unwrap();
        let c = "203.0.113.3:3478".parse().unwrap();
        let hint = p2pnet_nat::StunObservation {
            server: "203.0.113.99:3478".into(),
            mapped_address: Some("198.51.100.1:40000".into()),
            rtt_ms: Some(1),
            error: None,
        };
        assert_eq!(
            select_measurement_observers(
                &[a, a, "[2001:db8::1]:3478".parse().unwrap(), b, c],
                &[hint]
            ),
            [a, b, c]
        );
    }

    #[test]
    fn four_responsive_observers_retain_cross_address_grid_measurement() {
        let configured = [
            "203.0.113.1:3478".parse().unwrap(),
            "203.0.113.1:3479".parse().unwrap(),
            "203.0.113.2:3478".parse().unwrap(),
            "203.0.113.3:3478".parse().unwrap(),
        ];
        let hints = configured
            .iter()
            .map(|addr: &SocketAddr| p2pnet_nat::StunObservation {
                server: addr.to_string(),
                mapped_address: Some("198.51.100.1:40000".into()),
                rtt_ms: Some(5),
                error: None,
            })
            .collect::<Vec<_>>();
        let selected = select_measurement_observers(&configured, &hints);
        assert_eq!(selected.len(), 4);
        assert_ne!(selected[0].ip(), selected[1].ip());
        assert!(configured.iter().all(|addr| selected.contains(addr)));
    }

    #[test]
    fn regular_measurement_preference_rejects_gaps_and_unobserved_allocations() {
        let (mut samples, mut attempts, _) = grid(2);
        assert!(regular_allocation_measurement(&samples, &attempts));
        samples[1].observation.observed.set_port(51000);
        samples[2].observation.observed.set_port(51002);
        assert!(
            regular_allocation_measurement(&samples, &attempts),
            "another socket's allocator must not disable the regular primary tail"
        );
        samples
            .last_mut()
            .unwrap()
            .observation
            .observed
            .set_port(40012);
        assert!(!regular_allocation_measurement(&samples, &attempts));
        samples
            .last_mut()
            .unwrap()
            .observation
            .observed
            .set_port(40010);
        attempts.last_mut().unwrap().outcome = Outcome::SentUnobserved;
        assert!(!regular_allocation_measurement(&samples, &attempts));
    }

    fn grid(
        step: i32,
    ) -> (
        Vec<AllocationSample>,
        Vec<AllocationAttempt>,
        AllocationIdentity,
    ) {
        let pairs = [(0, 0), (1, 0), (1, 1), (0, 1), (0, 2), (0, 3)];
        let samples = pairs
            .iter()
            .enumerate()
            .map(|(sequence, (socket, observer))| AllocationSample {
                socket_id: *socket,
                observation: MappingObservation {
                    sequence: sequence as u16,
                    observer: format!("203.0.113.{}:3478", observer + 1).parse().unwrap(),
                    observed: SocketAddr::new(
                        "198.51.100.1".parse().unwrap(),
                        (40000 + sequence as i32 * step) as u16,
                    ),
                    sent_at_ms: 100 + sequence as u64 * 10,
                    responded_at_ms: 101 + sequence as u64 * 10,
                    local_endpoint: format!("192.0.2.1:{}", 5000 + socket).parse().unwrap(),
                },
            })
            .collect::<Vec<_>>();
        let attempts = samples
            .iter()
            .map(|sample| AllocationAttempt {
                sequence: sample.observation.sequence,
                local_endpoint: sample.observation.local_endpoint,
                destination: sample.observation.observer,
                sent_at_ms: sample.observation.sent_at_ms,
                datagram_bytes: 40,
                outcome: Outcome::Observed,
            })
            .collect();
        let identity = AllocationIdentity {
            network_generation: 7,
            measurement_generation: 9,
            egress: "192.0.2.1:4000".parse().unwrap(),
        };
        (samples, attempts, identity)
    }

    #[test]
    fn competing_allocations_keep_a_bounded_prediction_hypothesis_without_anchor_evidence() {
        for (ports, step, expected_prefix) in [
            (
                [40000, 40001, 40002, 40003, 40004, 40006],
                2,
                [40008, 40007, 40010],
            ),
            (
                [40010, 40009, 40008, 40005, 40003, 40000],
                -2,
                [39998, 39999, 39996],
            ),
        ] {
            let (mut samples, attempts, identity) = grid(1);
            for (sample, port) in samples.iter_mut().zip(ports) {
                sample.observation.observed.set_port(port);
            }
            let (allocation, rejection, prediction) = prepared_prediction(
                &samples,
                &attempts,
                identity,
                0,
                samples[0].observation.local_endpoint,
                HardHardMeasurementStats::default(),
                (3500, 3500),
                1000,
            );
            assert!(
                allocation.is_none(),
                "the irregular grid must never authorize Anchor"
            );
            assert_eq!(
                rejection,
                Some(AllocationEvidenceRejection::NoConsistentStep)
            );
            let prediction =
                prediction.expect("the complete primary tail still supplies hypotheses");
            assert_eq!(prediction.model.kind, PortModelKind::Linear { step });
            assert_eq!(prediction.model.confidence, 86);
            assert_eq!(&prediction.predicted_ports[..3], &expected_prefix);
            assert!(prediction.predicted_ports.len() <= p2pnet_nat::MAX_PREDICTED_PORTS);
            assert_eq!(prediction.model.sampled_at_ms, 130);
            assert_eq!(prediction.network_generation, identity.network_generation);
            assert_eq!(prediction.punch_generation, identity.measurement_generation);
        }
    }

    #[test]
    fn early_timeout_keeps_a_fresh_final_prediction_but_never_a_shared_anchor() {
        for step in [-1, 1] {
            let (mut samples, mut attempts, identity) = grid(step);
            attempts[1].outcome = Outcome::SentUnobserved;
            samples.remove(1);
            let (allocation, rejection, prediction) = prepared_prediction(
                &samples,
                &attempts,
                identity,
                0,
                samples[0].observation.local_endpoint,
                HardHardMeasurementStats::default(),
                (3500, 3500),
                1000,
            );
            assert!(allocation.is_none());
            assert_eq!(
                rejection,
                Some(AllocationEvidenceRejection::UnobservedAllocation)
            );
            let prediction =
                prediction.expect("complete primary suffix supplies its own real base");
            assert_eq!(prediction.model.sequence.len(), 3);
            assert_eq!(prediction.model.sampled_at_ms, 130);
            assert_eq!(
                prediction.model.kind,
                PortModelKind::FixedStep { step: step as i16 }
            );
            assert_eq!(prediction.predicted_ports[0], (40000 + 6 * step) as u16);
            assert_eq!(prediction.network_generation, identity.network_generation);
            assert_eq!(prediction.punch_generation, identity.measurement_generation);
        }
    }

    #[test]
    fn incomplete_tail_and_real_sample_expiry_still_disable_prediction() {
        for missing in [3, 4, 5] {
            let (mut samples, mut attempts, identity) = grid(1);
            attempts[missing].outcome = Outcome::SentUnobserved;
            samples.remove(missing);
            let (_, _, prediction) = prepared_prediction(
                &samples,
                &attempts,
                identity,
                0,
                samples[0].observation.local_endpoint,
                HardHardMeasurementStats::default(),
                (3500, 3500),
                1000,
            );
            assert!(prediction.is_none());
        }
        let (mut samples, mut attempts, identity) = grid(1);
        attempts[1].outcome = Outcome::SentUnobserved;
        samples.remove(1);
        let (_, _, prediction) = prepared_prediction(
            &samples,
            &attempts,
            identity,
            0,
            samples[0].observation.local_endpoint,
            HardHardMeasurementStats::default(),
            (3500, 3500),
            3000,
        );
        assert!(
            prediction.is_none(),
            "rebasing preserves the actual suffix sample time"
        );
    }

    #[test]
    fn adapted_three_response_tail_predicts_from_its_actual_last_send_without_an_anchor() {
        let (_, _, identity) = grid(1);
        let primary: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let mut attempts = Vec::new();
        let mut samples = Vec::new();
        for sequence in 0..4u16 {
            let observer = format!("203.0.113.{}:3478", sequence + 1).parse().unwrap();
            let sent_at_ms = match sequence {
                0 => 100,
                _ => 300 + u64::from(sequence - 1) * 250,
            };
            attempts.push(AllocationAttempt {
                sequence,
                local_endpoint: primary,
                destination: observer,
                sent_at_ms,
                datagram_bytes: 40,
                outcome: if sequence == 0 {
                    Outcome::SentUnobserved
                } else {
                    Outcome::Observed
                },
            });
            if sequence > 0 {
                samples.push(AllocationSample {
                    socket_id: 0,
                    observation: MappingObservation {
                        sequence,
                        observer,
                        observed: SocketAddr::new(
                            "198.51.100.1".parse().unwrap(),
                            40000 + sequence,
                        ),
                        sent_at_ms,
                        responded_at_ms: sent_at_ms + 250,
                        local_endpoint: primary,
                    },
                });
            }
        }
        let measurement = HardHardMeasurementStats {
            stun_datagrams_sent: 4,
            stun_bytes_sent: 160,
            stun_responses: 3,
            measurement_started_at_ms: Some(100),
            last_measurement_send_at_ms: Some(800),
            measurement_completed_at_ms: Some(1050),
            ..HardHardMeasurementStats::default()
        };
        let (allocation, rejection, prediction) = prepared_prediction(
            &samples,
            &attempts,
            identity,
            0,
            primary,
            measurement,
            (3600, 3500),
            1050,
        );
        assert!(allocation.is_none());
        assert_eq!(
            rejection,
            Some(AllocationEvidenceRejection::UnobservedAllocation)
        );
        let prediction =
            prediction.expect("three consecutive actual primary observations are enough");
        assert_eq!(prediction.model.sampled_at_ms, 300);
        assert_eq!(prediction.predicted_ports[0], 40004);
        assert_eq!(prediction.measurement.stun_datagrams_sent, 4);
        assert_eq!(
            prediction.measurement.last_measurement_send_at_ms,
            Some(800)
        );
        assert_eq!(attempts[0].outcome, Outcome::SentUnobserved);
        // The batch started at 100, but the independent observed tail really
        // started at 300. At 2700 it is 2400 ms old, not a stale 2600 ms model.
        assert!(validate_prepared_publication_timing(
            prediction.measurement.measurement_started_at_ms.unwrap(),
            Some(prediction.model.sampled_at_ms),
            2700,
            (3600, 3500),
        )
        .is_ok());
        assert_eq!(
            validate_prepared_publication_timing(100, None, 2700, (3600, 3500)),
            Err(AllocationEvidenceRejection::Stale),
            "full-grid or birthday-only evidence keeps the original age limit"
        );
    }

    #[test]
    fn independent_tail_publication_preserves_both_original_forecast_bounds() {
        use AllocationEvidenceRejection as Reject;
        assert_eq!(
            validate_prepared_publication_timing(100, Some(300), 2700, (3601, 3500)),
            Err(Reject::ForecastHorizonExceeded),
            "a later tail cannot hide a batch-to-send forecast over 3500 ms"
        );
        assert_eq!(
            validate_prepared_publication_timing(100, Some(300), 2700, (2700, 3500)),
            Err(Reject::ForecastExpired),
            "a fresh tail cannot move the original planned send forward"
        );
        assert_eq!(
            validate_prepared_publication_timing(100, Some(300), 2801, (3600, 3500)),
            Err(Reject::Stale),
            "freshness is still limited by the tail's actual sample time"
        );
        assert_eq!(
            validate_prepared_publication_timing(100, Some(99), 200, (3600, 3500)),
            Err(Reject::InconsistentOrder)
        );
        assert_eq!(
            validate_prepared_publication_timing(100, Some(300), 299, (3600, 3500)),
            Err(Reject::Stale)
        );
    }
}
