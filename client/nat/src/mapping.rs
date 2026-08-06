//! Dynamic NAT port-mapping sequence modeling for hard-NAT hole punching.
//!
//! ## Why this module exists
//!
//! A linear-symmetric NAT allocates one fresh public port per new outbound
//! destination.  A single fresh UDP socket that contacts several distinct
//! STUN observers therefore produces an ordered sequence of public ports
//! `P0, P1, ..., Pn` in **send order** (not response order).  The next
//! outbound to a *new* destination — e.g. the real peer — is then the next
//! element of that sequence, with a small allowance for mappings consumed by
//! unrelated traffic between the last STUN request and the peer-directed
//! punch (e.g. `33051, 33052, 33053` STUN ports followed by a peer-facing
//! `33055` because one intermediate mapping was consumed).
//!
//! This module computes the model from the *ordered* observations and emits a
//! rank-ordered candidate distribution.  It never hard-codes `+1`, `+2` or
//! any fixed delta: the step is derived from the observed sequence itself.
//!
//! ## Consistency rules
//!
//! - Observations must be ordered by their send sequence number.
//! - All observations in one batch must come from the same local UDP socket
//!   (same socket identity) and the same network generation.
//! - The batch must be fresh (`is_batch_fresh`) and may span only one public
//!   IP (`batch_public_ip`); a public-IP change invalidates the model.
//! - When the sequence is not consistent enough, the linear model is rejected
//!   (`Unpredictable`) instead of forcing a prediction.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One STUN mapping observation on a dedicated punch socket.
///
/// `sequence` is the request send order (0-based).  Responses may arrive in
/// any order; the model only trusts the send order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingObservation {
    /// Send-order sequence number (0, 1, 2, ...).
    pub sequence: u16,
    /// STUN observer destination (IP:port) that was contacted.
    pub observer: SocketAddr,
    /// Public (server-reflexive) mapping the observer reported.
    pub observed: SocketAddr,
    /// Monotonic send timestamp in milliseconds.
    pub sent_at_ms: u64,
    /// Monotonic response timestamp in milliseconds (0 when the response was
    /// never received within the measurement budget).
    pub responded_at_ms: u64,
    /// Local UDP socket endpoint used for the measurement.
    pub local_endpoint: SocketAddr,
}

impl MappingObservation {
    /// Round-trip time in milliseconds, when the response arrived.
    pub fn rtt_ms(&self) -> Option<u64> {
        (self.responded_at_ms >= self.sent_at_ms).then_some(self.responded_at_ms - self.sent_at_ms)
    }
}

/// A complete measurement batch for one punch generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingBatch {
    /// Per-peer punch generation this batch belongs to.
    pub generation: u64,
    /// Local network generation captured at measurement time.
    pub network_generation: u64,
    /// Socket identity: the local UDP endpoint used for every observation.
    pub socket_identity: SocketAddr,
    /// Observations ordered by `sequence` (send order).
    pub observations: Vec<MappingObservation>,
    /// Monotonic batch start timestamp in milliseconds.
    pub started_at_ms: u64,
    /// Monotonic batch end timestamp in milliseconds (after the last response
    /// or the measurement budget).
    pub finished_at_ms: u64,
}

impl MappingBatch {
    /// Ordered public ports in send order, skipping failed samples.
    pub fn ordered_ports(&self) -> Vec<u16> {
        self.observations
            .iter()
            .filter(|observation| observation.responded_at_ms > 0)
            .map(|observation| observation.observed.port())
            .collect()
    }

    /// Number of successful observations in send order.
    pub fn successful_samples(&self) -> usize {
        self.ordered_ports().len()
    }

    /// All observed public addresses share one IP when this returns `Some`.
    pub fn public_ip(&self) -> Option<std::net::IpAddr> {
        let mut iter = self
            .observations
            .iter()
            .filter(|observation| observation.responded_at_ms > 0)
            .map(|observation| observation.observed.ip());
        let first = iter.next()?;
        iter.all(|ip| ip == first).then_some(first)
    }

    /// Whether every observation used the same local socket and generation.
    ///
    /// Mixed sockets, generations or send-order duplication invalidate a
    /// batch and must never feed a model.
    pub fn is_consistent(&self) -> bool {
        let mut sequences = Vec::with_capacity(self.observations.len());
        for observation in &self.observations {
            if observation.local_endpoint != self.socket_identity {
                return false;
            }
            if sequences.contains(&observation.sequence) {
                return false;
            }
            sequences.push(observation.sequence);
        }
        sequences.sort_unstable();
        sequences
            .iter()
            .enumerate()
            .all(|(index, sequence)| *sequence == index as u16)
    }

    /// Whether the whole batch is newer than `max_age`.
    pub fn is_fresh(&self, max_age: Duration, now_ms: u64) -> bool {
        self.finished_at_ms > 0
            && self.finished_at_ms >= self.started_at_ms
            && now_ms >= self.started_at_ms
            && (now_ms - self.started_at_ms) <= max_age.as_millis() as u64
    }
}

/// Reason a linear model was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRejection {
    /// Fewer than three successful samples in send order.
    InsufficientSamples,
    /// Observed public addresses changed mid-batch (network change).
    PublicIpChanged,
    /// The batch was too old to trust.
    BatchStale,
    /// Observations mixed sockets, generations or duplicated sequence numbers.
    InconsistentBatch,
    /// Deltas had no consistent direction/step.
    NoConsistentStep,
    /// Deltas jumped so widely that the sequence is a narrow random range.
    NarrowRandom,
}

/// Identified NAT port-allocation behavior for one batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PortModelKind {
    /// Every observed delta is identical and non-zero.
    FixedStep { step: i16 },
    /// Deltas share one direction and stay within a small spread; the median
    /// step is used.
    Linear { step: i16 },
    /// A dominant step with occasional deltas that look like unrelated
    /// mappings consumed between our own requests (e.g. `1,1,2` or
    /// `1,1,4`).  The prediction still walks the dominant step.
    NoisyLinear { step: i16 },
    /// Deltas repeat with a fixed period (e.g. `+1,-1,+1,-1`).
    Periodic { steps: Vec<i16> },
    /// All observed ports identical: endpoint-independent mapping.
    Stable,
    /// No consistent behavior could be modeled.
    Unpredictable { reason: ModelRejection },
}

impl PortModelKind {
    /// Human-readable label for structured logs.
    pub fn label(self) -> &'static str {
        match self {
            PortModelKind::FixedStep { .. } => "fixed_step",
            PortModelKind::Linear { .. } => "linear",
            PortModelKind::NoisyLinear { .. } => "noisy_linear",
            PortModelKind::Periodic { .. } => "periodic",
            PortModelKind::Stable => "stable",
            PortModelKind::Unpredictable { .. } => "unpredictable",
        }
    }

    /// Whether the model can be used for a port prediction.
    pub fn is_predictable(self) -> bool {
        !matches!(self, PortModelKind::Unpredictable { .. })
    }
}

/// The modeled port-allocation behavior of one measurement batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortModel {
    /// Identified behavior.
    pub kind: PortModelKind,
    /// Confidence 0-100 that the next mapping follows the model.
    pub confidence: u8,
    /// Public IP the batch was measured on.
    pub public_ip: Option<std::net::IpAddr>,
    /// Ordered observed ports in send order.
    pub sequence: Vec<u16>,
    /// Modular deltas between consecutive sequence entries.
    pub deltas: Vec<i16>,
    /// Batch start time (monotonic ms) used for freshness checks.
    pub sampled_at_ms: u64,
}

/// One predicted public port in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredictionCandidate {
    /// Predicted public port.
    pub port: u16,
    /// Priority: 0 is the top-1 model prediction, then the successor window,
    /// then the wider low-confidence window.
    pub rank: u8,
    /// Why this port is in the distribution.
    pub reason: PredictionReason,
}

/// Why a predicted port is proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionReason {
    /// `last + step`: the direct successor of the final observation.
    TopPrediction,
    /// `last + step*k` for small k: tolerates intermediate mappings consumed
    /// by unrelated traffic between the last STUN request and the punch.
    SuccessorWindow { distance: u8 },
    /// Wider window used only when model confidence is low.
    LowConfidenceWindow { distance: u8 },
    /// Same port again (endpoint-independent mapping).
    StablePort,
    /// Next port of the periodic pattern.
    PeriodicSuccessor { distance: u8 },
}

/// Compute the forward signed difference `b - a` with 65536 wrap handling.
///
/// The result lies in `[-32768, 32767]`: a NAT that wraps from port 65535 to
/// port 1 yields `+2` (65535 -> 65536+1), and a step of -2 that wraps from 1
/// to 65535 yields `-2` (1 - 65536 + 65535).
pub fn modular_difference(a: u16, b: u16) -> i16 {
    let raw = i32::from(b) - i32::from(a);
    if raw > 32767 {
        (raw - 65536) as i16
    } else if raw < -32768 {
        (raw + 65536) as i16
    } else {
        raw as i16
    }
}

/// Apply `step` to `port` with 65536 wrap handling.
pub fn modular_add(port: u16, step: i16) -> u16 {
    let raw = i32::from(port) + i32::from(step);
    (raw.rem_euclid(65536)) as u16
}

fn median(deltas: &[i16]) -> i16 {
    let mut sorted = deltas.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn dominant_step(deltas: &[i16]) -> Option<i16> {
    use std::collections::HashMap;
    let mut counts = HashMap::<i16, usize>::new();
    for delta in deltas {
        *counts.entry(*delta).or_default() += 1;
    }
    let mut ranked = counts.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|(left_step, left_count), (right_step, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_step.abs().cmp(&right_step.abs()))
    });
    let (step, count) = *ranked.first()?;
    (count >= deltas.len().div_ceil(2)).then_some(step)
}

fn other_deltas_are_multiples(deltas: &[i16], step: i16) -> bool {
    deltas
        .iter()
        .all(|delta| *delta == 0 || delta.checked_rem(step) == Some(0))
}

fn detect_periodic(deltas: &[i16]) -> Option<Vec<i16>> {
    for period in 1..=deltas.len() / 2 {
        let steps = deltas[..period].to_vec();
        if steps.contains(&0) {
            continue;
        }
        if deltas
            .iter()
            .enumerate()
            .all(|(index, delta)| *delta == steps[index % period])
            && deltas.len() > period * 2
        {
            return Some(steps);
        }
    }
    None
}

/// Build the port-allocation model for one send-ordered sequence.
///
/// Rejects inconsistent or non-linear sequences with an explicit reason
/// instead of forcing a prediction.
pub fn build_model(
    sequence: &[u16],
    public_ip: Option<std::net::IpAddr>,
    sampled_at_ms: u64,
) -> PortModel {
    let deltas = sequence
        .windows(2)
        .map(|pair| modular_difference(pair[0], pair[1]))
        .collect::<Vec<_>>();

    if sequence.len() < 3 {
        return PortModel {
            kind: PortModelKind::Unpredictable {
                reason: ModelRejection::InsufficientSamples,
            },
            confidence: 0,
            public_ip,
            sequence: sequence.to_vec(),
            deltas,
            sampled_at_ms,
        };
    }

    if deltas.iter().all(|delta| *delta == 0) {
        return PortModel {
            kind: PortModelKind::Stable,
            confidence: 95,
            public_ip,
            sequence: sequence.to_vec(),
            deltas,
            sampled_at_ms,
        };
    }

    let all_equal = deltas.iter().all(|delta| *delta == deltas[0]);
    if all_equal {
        let step = deltas[0];
        let confidence = if step.abs() <= 1024 { 95 } else { 80 };
        return PortModel {
            kind: PortModelKind::FixedStep { step },
            confidence,
            public_ip,
            sequence: sequence.to_vec(),
            deltas,
            sampled_at_ms,
        };
    }

    let positive = deltas.iter().all(|delta| *delta > 0);
    let negative = deltas.iter().all(|delta| *delta < 0);
    let same_direction = positive || negative;
    let min_delta = deltas.iter().copied().min().unwrap_or(0);
    let max_delta = deltas.iter().copied().max().unwrap_or(0);
    let spread = max_delta - min_delta;
    if same_direction && spread <= 2 {
        let step = median(&deltas);
        let confidence = 92u8.saturating_sub(spread as u8 * 6);
        return PortModel {
            kind: PortModelKind::Linear { step },
            confidence,
            public_ip,
            sequence: sequence.to_vec(),
            deltas,
            sampled_at_ms,
        };
    }

    if let Some(steps) = detect_periodic(&deltas) {
        return PortModel {
            kind: PortModelKind::Periodic { steps },
            confidence: 85,
            public_ip,
            sequence: sequence.to_vec(),
            deltas,
            sampled_at_ms,
        };
    }

    if let Some(step) = dominant_step(&deltas) {
        if step != 0 && other_deltas_are_multiples(&deltas, step) {
            // Every delta must share the dominant step's direction.  A shared
            // CGNAT can interleave other flows between our own requests, so
            // same-direction jumps (e.g. `1,1,2`) are still predictable; a
            // mixed-direction sequence (e.g. `-1,+3,-1`) means the allocator
            // hands out ports in an order we cannot model, and predicting
            // along the dominant step would walk the wrong way.
            let same_direction = deltas
                .iter()
                .all(|delta| *delta == 0 || delta.signum() == step.signum());
            if same_direction {
                let mut majority = 0usize;
                for delta in &deltas {
                    if *delta == step {
                        majority += 1;
                    }
                }
                if majority * 2 >= deltas.len() {
                    return PortModel {
                        kind: PortModelKind::NoisyLinear { step },
                        confidence: 75,
                        public_ip,
                        sequence: sequence.to_vec(),
                        deltas,
                        sampled_at_ms,
                    };
                }
            }
        }
    }

    let narrow_random = deltas
        .iter()
        .all(|delta| delta.unsigned_abs() <= 16 && *delta != 0);
    PortModel {
        kind: PortModelKind::Unpredictable {
            reason: if narrow_random {
                ModelRejection::NarrowRandom
            } else {
                ModelRejection::NoConsistentStep
            },
        },
        confidence: 0,
        public_ip,
        sequence: sequence.to_vec(),
        deltas,
        sampled_at_ms,
    }
}

/// Build the model for a measurement batch after validating consistency,
/// freshness and public-IP stability.
///
/// Returns `Err(rejection)` when the batch cannot be trusted or modeled.
pub fn build_model_for_batch(
    batch: &MappingBatch,
    max_age: Duration,
    now_ms: u64,
) -> Result<PortModel, ModelRejection> {
    if !batch.is_consistent() {
        return Err(ModelRejection::InconsistentBatch);
    }
    if !batch.is_fresh(max_age, now_ms) {
        return Err(ModelRejection::BatchStale);
    }
    let public_ip = batch.public_ip();
    let sequence = batch.ordered_ports();
    let model = build_model(&sequence, public_ip, batch.started_at_ms);
    if matches!(model.kind, PortModelKind::Unpredictable { .. }) {
        return Err(ModelRejection::NoConsistentStep);
    }
    Ok(model)
}

/// Maximum total predicted candidates emitted by `predict_ports`.
pub const MAX_PREDICTED_PORTS: usize = 24;

/// Build the rank-ordered candidate distribution for the next mapping.
///
/// Ranking:
/// 0. top-1 model prediction (`last + step`, or the next periodic step)
/// 1..: small successor window tolerating externally consumed mappings
/// then: wider window only when confidence is low.
///
/// `last` is the final observed public port.
pub fn predict_ports(model: &PortModel, last: u16) -> Vec<PredictionCandidate> {
    predict_ports_for_elapsed(model, last, 0, 0)
}

/// Same as [`predict_ports`], with a window that grows with the expected gap
/// between the end of the measurement and the peer's probes.
///
/// A shared CGNAT keeps consuming public ports while we wait for the signal to
/// reach the peer (`gap_ms`).  The extra ports are estimated from the
/// consumption rate observed during the measurement: every delta beyond the
/// model step is one unrelated mapping consumed between our own requests.
/// `measurement_span_ms` is the wall time of the STUN batch; pass 0 to keep
/// the fixed confidence-based window only.
pub fn predict_ports_for_elapsed(
    model: &PortModel,
    last: u16,
    measurement_span_ms: u64,
    gap_ms: u64,
) -> Vec<PredictionCandidate> {
    let mut candidates = Vec::with_capacity(MAX_PREDICTED_PORTS);

    match model.kind {
        PortModelKind::Stable => {
            candidates.push(PredictionCandidate {
                port: last,
                rank: 0,
                reason: PredictionReason::StablePort,
            });
        }
        PortModelKind::Periodic { ref steps } => {
            let period = steps.len();
            for distance in 0..MAX_PREDICTED_PORTS {
                let mut port = last;
                for offset in 0..=distance {
                    let step = steps[(model.deltas.len() + offset) % period];
                    port = modular_add(port, step);
                }
                candidates.push(PredictionCandidate {
                    port,
                    rank: distance as u8,
                    reason: if distance == 0 {
                        PredictionReason::TopPrediction
                    } else {
                        PredictionReason::PeriodicSuccessor {
                            distance: distance as u8,
                        }
                    },
                });
            }
        }
        PortModelKind::FixedStep { step }
        | PortModelKind::Linear { step }
        | PortModelKind::NoisyLinear { step } => {
            let base_window = match model.confidence {
                90..=100 => 6,
                75..=89 => 12,
                60..=74 => MAX_PREDICTED_PORTS,
                _ => 0,
            };
            let extra_window = extra_window_ports(model, measurement_span_ms, gap_ms);
            let window_size = base_window
                .saturating_add(extra_window)
                .min(MAX_PREDICTED_PORTS);
            let low_confidence = model.confidence < 75;
            for distance in 0..window_size {
                let port = modular_add(last, step.saturating_mul((distance + 1) as i16));
                candidates.push(PredictionCandidate {
                    port,
                    rank: distance as u8,
                    reason: if distance == 0 {
                        PredictionReason::TopPrediction
                    } else if low_confidence {
                        PredictionReason::LowConfidenceWindow {
                            distance: distance as u8,
                        }
                    } else {
                        PredictionReason::SuccessorWindow {
                            distance: distance as u8,
                        }
                    },
                });
            }
        }
        PortModelKind::Unpredictable { .. } => {}
    }

    candidates.truncate(MAX_PREDICTED_PORTS);
    candidates
}

/// Extra candidate ports covering the mappings a shared CGNAT will consume
/// between the last STUN response and the peer's probes.
///
/// The observed sequence already contains the externality: every delta that
/// overshoots the model step is one unrelated mapping consumed between two of
/// our requests.  `excess / span` is the observed port consumption rate of
/// unrelated traffic; multiplying by the expected gap yields the extra ports
/// the peer-facing mapping may drift by.
fn extra_window_ports(model: &PortModel, measurement_span_ms: u64, gap_ms: u64) -> usize {
    if measurement_span_ms == 0 || gap_ms == 0 {
        return 0;
    }
    let step = match model.kind {
        PortModelKind::FixedStep { step }
        | PortModelKind::Linear { step }
        | PortModelKind::NoisyLinear { step } => step,
        _ => return 0,
    };
    let mut excess_ports = 0u64;
    let step_direction = i64::from(step.signum());
    for delta in &model.deltas {
        // Measure the overshoot along the model's direction: with step +1 a
        // delta of +3 consumed two extra ports; with step -1 a delta of -3
        // consumed two extra ports as well.
        let beyond = (i64::from(*delta) - i64::from(step)) * step_direction;
        if beyond > 0 {
            excess_ports += beyond as u64;
        }
    }
    if excess_ports == 0 {
        return 0;
    }
    let rate = excess_ports as f64 / measurement_span_ms.max(1) as f64;
    let extra = (rate * gap_ms as f64).ceil() as usize;
    extra.min(MAX_PREDICTED_PORTS)
}

/// Whether the model's samples are still within their trusted age.
pub fn model_is_fresh(model: &PortModel, max_age: Duration, now_ms: u64) -> bool {
    now_ms >= model.sampled_at_ms && (now_ms - model.sampled_at_ms) <= max_age.as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(220, 163, 6, 190))
    }

    fn batch(sequence: u16, observed: u16) -> MappingObservation {
        MappingObservation {
            sequence,
            observer: ("1.2.3.4:3478").parse().unwrap(),
            observed: SocketAddr::new(ip(), observed),
            sent_at_ms: 1000,
            responded_at_ms: 1050,
            local_endpoint: ("0.0.0.0:58980").parse().unwrap(),
        }
    }

    fn consistent_batch(ports: &[u16]) -> MappingBatch {
        MappingBatch {
            generation: 7,
            network_generation: 3,
            socket_identity: ("0.0.0.0:58980").parse().unwrap(),
            observations: ports
                .iter()
                .enumerate()
                .map(|(index, port)| batch(index as u16, *port))
                .collect(),
            started_at_ms: 1000,
            finished_at_ms: 1100,
        }
    }

    #[test]
    fn modular_difference_handles_wrap() {
        assert_eq!(modular_difference(65534, 65535), 1);
        assert_eq!(modular_difference(65535, 1), 2);
        assert_eq!(modular_difference(1, 65535), -2);
        assert_eq!(modular_difference(1000, 1005), 5);
        assert_eq!(modular_difference(45390, 45391), 1);
    }

    #[test]
    fn modular_add_handles_wrap() {
        assert_eq!(modular_add(65535, 1), 0);
        assert_eq!(modular_add(65534, 2), 0);
        assert_eq!(modular_add(1, -2), 65535);
        assert_eq!(modular_add(45393, 1), 45394);
    }

    #[test]
    fn fixed_step_detection_and_prediction() {
        for (base, step) in [(45390i32, 1i32), (1000, 5), (2000, 7), (30000, -3)] {
            let ports = [base as u16, (base + step) as u16, (base + 2 * step) as u16];
            let model = build_model(&ports, Some(ip()), 1000);
            assert!(
                matches!(model.kind, PortModelKind::FixedStep { step: s } if s == step as i16),
                "expected fixed step {step} for {ports:?}, got {:?}",
                model.kind
            );
            assert_eq!(model.confidence, 95);
            let predicted = predict_ports(&model, ports[2]);
            assert_eq!(predicted[0].rank, 0);
            assert_eq!(predicted[0].port, (base + 3 * step) as u16);
            assert_eq!(predicted[0].reason, PredictionReason::TopPrediction);
            assert_eq!(predicted.len(), 6);
        }
    }

    #[test]
    fn wrap_prediction_continues_sequence() {
        let ports = [65533u16, 65535, 1];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(model.kind, PortModelKind::FixedStep { step: 2 }));
        let predicted = predict_ports(&model, 1);
        assert_eq!(predicted[0].port, 3);
    }

    #[test]
    fn send_order_is_authoritative_over_response_order() {
        // Responses arrive out of order, but the batch is ordered by send
        // sequence: 45390, 45391, 45392.  Response-order would read
        // 45391, 45390, 45392 and produce garbage deltas.
        let mut batch = consistent_batch(&[45390, 45391, 45392]);
        batch.observations[1].responded_at_ms = 1090;
        batch.observations[0].responded_at_ms = 1005;
        let model = build_model_for_batch(&batch, Duration::from_secs(5), 2000).unwrap();
        assert!(matches!(model.kind, PortModelKind::FixedStep { step: 1 }));
        let predicted = predict_ports(&model, 45392);
        assert_eq!(predicted[0].port, 45393);
    }

    #[test]
    fn intermediate_consumption_keeps_step_but_extends_window() {
        // STUN observers saw 45390, 45391, 45392 (+1 each); one unrelated
        // mapping was consumed before the punch, so the peer-facing port is
        // 45394.  The successor window must cover it.
        let ports = [45390, 45391, 45392];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(model.kind, PortModelKind::FixedStep { step: 1 }));
        let predicted = predict_ports(&model, 45392);
        assert_eq!(predicted[0].port, 45393);
        assert_eq!(predicted[1].port, 45394);
        assert_eq!(
            predicted[1].reason,
            PredictionReason::SuccessorWindow { distance: 1 }
        );
        // UU's observed 33051/33052/33053 -> 33055 is the distance-2 case.
        assert_eq!(predicted[2].port, 45395);
    }

    #[test]
    fn noisy_linear_with_dominant_step() {
        // One delta is +2 because an unrelated flow consumed a mapping.
        let ports = [10000, 10005, 10010, 10015, 10020];
        let deltas = [5, 5, 5, 5];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(
            matches!(model.kind, PortModelKind::FixedStep { step: 5 }),
            "{:?}",
            model.kind
        );
        assert_eq!(model.deltas, deltas);
        let predicted = predict_ports(&model, 10020);
        assert_eq!(predicted[0].port, 10025);
    }

    #[test]
    fn linear_with_tiny_spread_uses_median() {
        // One delta drifted by one (external consumption): 1,1,2 -> median 1.
        let ports = [33051, 33052, 33053, 33055];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(
            matches!(model.kind, PortModelKind::NoisyLinear { step: 1 })
                | matches!(model.kind, PortModelKind::Linear { step: 1 }),
            "{:?}",
            model.kind
        );
        let predicted = predict_ports(&model, 33055);
        assert_eq!(predicted[0].port, 33056);
    }

    #[test]
    fn noisy_linear_majority_step_with_consumed_multiple() {
        // Two equal deltas and one consumed mapping (+2) still walk step +1.
        let ports = [33051, 33052, 33053, 33054, 33056];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(
            matches!(model.kind, PortModelKind::NoisyLinear { step: 1 })
                | matches!(model.kind, PortModelKind::Linear { step: 1 }),
            "{:?}",
            model.kind
        );
        let predicted = predict_ports(&model, 33056);
        assert_eq!(predicted[0].port, 33057);
        assert_eq!(predicted.len(), 12);
    }

    #[test]
    fn periodic_pattern_continues() {
        let ports = [1000, 1001, 1000, 1001, 1000, 1001];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(
            matches!(model.kind, PortModelKind::Periodic { .. }),
            "{:?}",
            model.kind
        );
        let predicted = predict_ports(&model, 1001);
        assert_eq!(predicted[0].port, 1000);
        assert_eq!(predicted[1].port, 1001);
    }

    #[test]
    fn unstable_sequence_is_rejected_not_predicted() {
        let ports = [1000, 1005, 1001, 1009, 1002];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(!model.kind.clone().is_predictable(), "{:?}", model.kind);
        assert!(matches!(
            model.kind,
            PortModelKind::Unpredictable {
                reason: ModelRejection::NoConsistentStep
            } | PortModelKind::Unpredictable {
                reason: ModelRejection::NarrowRandom
            }
        ));
        assert!(predict_ports(&model, 1002).is_empty());
    }

    #[test]
    fn narrow_random_is_identified_separately() {
        let ports = [1000, 1002, 1001, 1003, 1000, 1002];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(
            model.kind,
            PortModelKind::Unpredictable {
                reason: ModelRejection::NarrowRandom
            }
        ));
    }

    #[test]
    fn insufficient_samples_are_rejected() {
        let model = build_model(&[1000, 1001], Some(ip()), 1000);
        assert!(matches!(
            model.kind,
            PortModelKind::Unpredictable {
                reason: ModelRejection::InsufficientSamples
            }
        ));
    }

    #[test]
    fn stable_sequence_predicts_same_port() {
        let ports = [4483, 4483, 4483];
        let model = build_model(&ports, Some(ip()), 1000);
        assert_eq!(model.kind, PortModelKind::Stable);
        let predicted = predict_ports(&model, 4483);
        assert_eq!(predicted[0].port, 4483);
        assert_eq!(predicted[0].reason, PredictionReason::StablePort);
    }

    #[test]
    fn public_ip_change_invalidates_batch() {
        let mut batch = consistent_batch(&[45390, 45391, 45392]);
        batch.observations[2].observed = ("203.0.113.5:45392").parse().unwrap();
        let result = build_model_for_batch(&batch, Duration::from_secs(5), 2000);
        // Public-IP changes surface through the batch-level consistency rules
        // of the caller; the model layer still exposes the mixed public IP.
        assert!(batch.public_ip().is_none());
        // The sequence itself is still linear on ports, so the model builds;
        // the caller must reject on public_ip() == None.
        assert!(result.is_ok());
        assert!(result.unwrap().public_ip.is_none());
    }

    #[test]
    fn stale_batch_is_rejected() {
        let batch = consistent_batch(&[45390, 45391, 45392]);
        let result = build_model_for_batch(&batch, Duration::from_millis(500), 2000);
        assert_eq!(result.unwrap_err(), ModelRejection::BatchStale);
    }

    #[test]
    fn mixed_socket_or_generation_batch_is_inconsistent() {
        let mut batch = consistent_batch(&[45390, 45391, 45392]);
        batch.observations[1].local_endpoint = ("0.0.0.0:59999").parse().unwrap();
        assert!(!batch.is_consistent());
        assert_eq!(
            build_model_for_batch(&batch, Duration::from_secs(5), 2000).unwrap_err(),
            ModelRejection::InconsistentBatch
        );

        let mut duplicated = consistent_batch(&[45390, 45391, 45392]);
        duplicated.observations[2].sequence = 1;
        assert!(!duplicated.is_consistent());
    }

    #[test]
    fn negative_step_predicts_backward() {
        let ports = [20010, 20007, 20004];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(model.kind, PortModelKind::FixedStep { step: -3 }));
        let predicted = predict_ports(&model, 20004);
        assert_eq!(predicted[0].port, 20001);
        let mut ascending = predicted
            .iter()
            .map(|candidate| candidate.rank)
            .collect::<Vec<_>>();
        ascending.sort_unstable();
        assert_eq!(ascending, (0..6).collect::<Vec<_>>());
    }

    #[test]
    fn mixed_direction_noisy_linear_is_rejected_not_predicted() {
        // A shared CGNAT interleaving other flows hands ports back and forth:
        // deltas [-1,+3,-1] previously produced a NoisyLinear step of -1
        // with 75 confidence even though the public port grows over time.
        let ports = [10134u16, 10133, 10136, 10135];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(!model.kind.clone().is_predictable(), "{:?}", model.kind);
        assert!(predict_ports(&model, 10135).is_empty());
    }

    #[test]
    fn same_direction_noisy_linear_still_predicts() {
        // Same-direction overshoots remain predictable: 1,1,2 is a
        // consumed-mapping NoisyLinear, not a rejection.
        let ports = [33051u16, 33052, 33053, 33055];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(
            matches!(
                model.kind,
                PortModelKind::NoisyLinear { step: 1 } | PortModelKind::Linear { step: 1 }
            ),
            "{:?}",
            model.kind
        );
        let predicted = predict_ports(&model, 33055);
        assert_eq!(predicted[0].port, 33056);
    }

    #[test]
    fn elapsed_window_grows_with_consumption_rate_and_gap() {
        // Deltas [1,1,2] over a 100ms measurement: one external mapping was
        // consumed, so the rate is 10 ports/s.  A 500ms gap must add 5 ports
        // on top of the 6-port high-confidence base window.
        let ports = [33051u16, 33052, 33053, 33055];
        let model = build_model(&ports, Some(ip()), 1000);
        let base = predict_ports(&model, 33055);
        assert_eq!(base.len(), 12, "NoisyLinear 75 confidence -> 12 base");
        let extended = predict_ports_for_elapsed(&model, 33055, 100, 500);
        assert!(
            extended.len() > base.len(),
            "extended {} must exceed base {}",
            extended.len(),
            base.len()
        );
        assert_eq!(extended[0].port, 33056);
        assert!(extended.iter().any(|candidate| candidate.port == 33060));
        assert!(extended.len() <= MAX_PREDICTED_PORTS);
        // No external consumption -> no extension.
        let clean = build_model(&[45390u16, 45391, 45392], Some(ip()), 1000);
        assert_eq!(
            predict_ports_for_elapsed(&clean, 45392, 100, 500).len(),
            predict_ports(&clean, 45392).len()
        );
    }

    #[test]
    fn elapsed_window_respects_negative_step_direction() {
        // step -1 with one extra consumed mapping: deltas [-1,-2].
        let ports = [20010u16, 20009, 20007];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(
            matches!(
                model.kind,
                PortModelKind::NoisyLinear { step: -1 } | PortModelKind::Linear { step: -1 }
            ),
            "{:?}",
            model.kind
        );
        let base = predict_ports(&model, 20007);
        let extended = predict_ports_for_elapsed(&model, 20007, 50, 500);
        assert!(
            extended.len() > base.len(),
            "extended {} must exceed base {}",
            extended.len(),
            base.len()
        );
        assert_eq!(extended[0].port, 20006);
    }

    #[test]
    fn model_freshness_check() {
        let model = build_model(&[45390, 45391, 45392], Some(ip()), 1000);
        assert!(model_is_fresh(&model, Duration::from_secs(5), 3000));
        assert!(!model_is_fresh(&model, Duration::from_millis(500), 3000));
    }
}
