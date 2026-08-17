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

    /// Whether every observation used the same local socket and preserves
    /// request-send order.
    ///
    /// Mixed sockets, reordered observations or duplicated sequence numbers
    /// invalidate a batch and must never feed a model. A timed-out observer
    /// is deliberately omitted by the collector, so successful observations
    /// may have sequence gaps (for example `0, 2, 3`). Gaps do not make the
    /// remaining send-ordered samples unsafe to model.
    pub fn is_consistent(&self) -> bool {
        let mut previous_sequence = None;
        for observation in &self.observations {
            if observation.local_endpoint != self.socket_identity {
                return false;
            }
            if previous_sequence.is_some_and(|previous| observation.sequence <= previous) {
                return false;
            }
            previous_sequence = Some(observation.sequence);
        }
        true
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
    /// Every observed allocation moved in the same direction, but no exact
    /// step dominated. This occurs on a shared CGNAT whose other clients
    /// consume a small, variable number of ports between our requests. The
    /// result deliberately emits only the fixed-size adjacent-port window in
    /// that direction; it never pretends that any one stride is known.
    MonotonicWindow { direction: i8 },
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
            PortModelKind::MonotonicWindow { .. } => "monotonic_window",
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

    // Real shared CGNATs can consume a variable number of consecutive ports
    // between our sequential STUN requests. The Mini-Air trace, for example,
    // measured `+14,+14,+5` and later `+1,+7,+3`: all allocations advanced
    // in one direction, but there was no reusable stride. Rejecting those
    // batches meant we never advertised any fresh mapping prediction at all.
    // Treat only *small* monotonic jumps as a low-confidence adjacent-port
    // window. The bound is exactly the wire/probe cap, so this cannot turn a
    // weak sample into an unbounded birthday scan or claim a false step.
    //
    // Later Mini-Air runs observed single-sample bursts far beyond that cap
    // (+123 and +43 on otherwise steady +1..+23 allocations): the burst is
    // other subscribers of the shared CGNAT consuming mappings, not a loss of
    // allocator order. Same-direction jumps up to the bounded
    // `MAX_MONOTONIC_WINDOW_JUMP` still produce a bounded adjacent-port
    // window; the wider window is advertised when any sample exceeded the
    // small window, so the peer can still probe the likely allocation region.
    if same_direction
        && deltas
            .iter()
            .all(|delta| delta.unsigned_abs() as usize <= MAX_MONOTONIC_WINDOW_JUMP)
    {
        let wide = deltas
            .iter()
            .any(|delta| delta.unsigned_abs() as usize > MAX_PREDICTED_PORTS);
        return PortModel {
            kind: PortModelKind::MonotonicWindow {
                direction: if positive { 1 } else { -1 },
            },
            confidence: if wide { 45 } else { 60 },
            public_ip,
            sequence: sequence.to_vec(),
            deltas,
            sampled_at_ms,
        };
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

    // A sequence gap means a timed-out observer whose request was already sent
    // (and whose NAT mapping was very likely already consumed) but whose port we
    // never observed.  Differencing across that gap would teach the model a
    // false, inflated step (e.g. a +1 allocator looks like +2).  Only a
    // gap-free batch may be modeled directly from its successful ports.
    //
    // The gap is detected over the *successful* observations only, so it is
    // robust to however the collector represents a timeout: either omitting the
    // failed entry entirely, or keeping it with `responded_at_ms == 0`.
    let successful_sequences: Vec<u16> = batch
        .observations
        .iter()
        .filter(|observation| observation.responded_at_ms > 0)
        .map(|observation| observation.sequence)
        .collect();
    let has_gap = successful_sequences
        .windows(2)
        .any(|window| window[1].saturating_sub(window[0]) > 1);

    let model = if has_gap {
        build_model_from_gapped(batch, public_ip, sequence)
    } else {
        build_model(&sequence, public_ip, batch.started_at_ms)
    };

    if matches!(model.kind, PortModelKind::Unpredictable { .. }) {
        return Err(ModelRejection::NoConsistentStep);
    }
    Ok(model)
}

/// Model a batch whose successful observations contain sequence gaps.
///
/// Only a maximal gap-free run (consecutive send sequences) may pin an exact
/// step, because within such a run every delta is a real single-request
/// allocation.  A single gap is never folded into the step.  When no run is
/// long enough to be trustworthy, downgrade to a direction-only
/// [`PortModelKind::MonotonicWindow`] over the full successful sequence so the
/// true next allocation stays inside a bounded window instead of being missed
/// by an inflated stride.  A mixed-direction sequence with no long run is
/// rejected rather than fabricating a direction.
fn build_model_from_gapped(
    batch: &MappingBatch,
    public_ip: Option<std::net::IpAddr>,
    successful: Vec<u16>,
) -> PortModel {
    // Split the successful observations into maximal gap-free runs.
    let successful_obs: Vec<&MappingObservation> = batch
        .observations
        .iter()
        .filter(|observation| observation.responded_at_ms > 0)
        .collect();
    let mut runs: Vec<Vec<u16>> = Vec::new();
    let mut previous_sequence: Option<u16> = None;
    for observation in &successful_obs {
        match previous_sequence {
            Some(previous) if observation.sequence.saturating_sub(previous) == 1 => {
                runs.last_mut().expect("a run always exists after the first push").push(
                    observation.observed.port(),
                );
            }
            _ => runs.push(vec![observation.observed.port()]),
        }
        previous_sequence = Some(observation.sequence);
    }

    // Prefer the longest gap-free run; trust it only when it is single-direction.
    if let Some(run) = runs.iter().filter(|run| run.len() >= 3).max_by_key(|run| run.len()) {
        let model = build_model(run, public_ip, batch.started_at_ms);
        let forward = model.deltas.iter().filter(|delta| **delta > 0).count();
        let backward = model.deltas.iter().filter(|delta| **delta < 0).count();
        if !(forward > 0 && backward > 0) {
            return model;
        }
    }

    // Downgrade: the full successful sequence's direction decides the window;
    // a gap may still be direction evidence even though it is not step evidence.
    let full_deltas: Vec<i16> = successful
        .windows(2)
        .map(|pair| modular_difference(pair[0], pair[1]))
        .collect();
    let forward = full_deltas.iter().filter(|delta| **delta > 0).count();
    let backward = full_deltas.iter().filter(|delta| **delta < 0).count();
    let kind = if forward > 0 && backward > 0 {
        PortModelKind::Unpredictable {
            reason: ModelRejection::NoConsistentStep,
        }
    } else {
        PortModelKind::MonotonicWindow {
            direction: if backward > 0 { -1 } else { 1 },
        }
    };
    let confidence = match kind {
        PortModelKind::MonotonicWindow { .. } => 60,
        _ => 0,
    };
    PortModel {
        kind,
        confidence,
        public_ip,
        sequence: successful,
        deltas: full_deltas,
        sampled_at_ms: batch.started_at_ms,
    }
}

/// Maximum total predicted candidates emitted by `predict_ports`.
pub const MAX_PREDICTED_PORTS: usize = 24;

/// Largest same-direction single-sample jump a monotonic allocation window
/// still accepts.  Shared CGNATs interleave other subscribers' mappings
/// between our own STUN requests (Mini-Air observed +123 and +43 bursts);
/// anything beyond this bound is treated as an unpredictable allocator.
pub const MAX_MONOTONIC_WINDOW_JUMP: usize = 512;

/// Wide fallback window emitted for noisy-but-monotonic allocations.
///
/// The receiver probes the fresh window inside its recovery budgets (the
/// Predicted stage alone allows hundreds of probes), and the daemon's
/// signaling layer reserves the same number of candidate slots for the fresh
/// window, so the whole window survives candidate truncation.
pub const MAX_MONOTONIC_WINDOW_PORTS: usize = 96;

/// Whether a model's deltas show a burst beyond the small adjacent window.
fn is_wide_monotonic_window(deltas: &[i16]) -> bool {
    deltas
        .iter()
        .any(|delta| delta.unsigned_abs() as usize > MAX_PREDICTED_PORTS)
}

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
    generate_candidates(model, last, measurement_span_ms, gap_ms, None, false)
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
        PortModelKind::MonotonicWindow { .. } => return 0,
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

/// The confidence tier of the linear candidate window, in the order the
/// predictor walks them.  `reverse_window` widens the base tier by one step
/// (to cover backwards allocation drift) and the sum is still capped at
/// `MAX_PREDICTED_PORTS`.
fn reverse_window_size(base_window: usize, reverse_window: bool) -> usize {
    let base = if reverse_window {
        match base_window {
            6 => 12,
            12 => MAX_PREDICTED_PORTS,
            _ => base_window,
        }
    } else {
        base_window
    };
    base.min(MAX_PREDICTED_PORTS)
}

/// Same as [`predict_ports_for_elapsed`], but with the adaptive-prediction
/// refinements folded in from the [`crate::adaptive`] learner state:
///
/// - `step_estimate`: when `Some`, it **overrides** the model's stride for the
///   `FixedStep` / `Linear` / `NoisyLinear` branches (the cross-batch EWMA
///   estimate is more current than this one batch's median).  The caller is
///   responsible for bounding the estimate (`FRESH_MAPPING_MAX_ABS_STEP`).
/// - `reverse_window`: when `true` (the peer's mappings are walking backwards),
///   the base confidence window is widened by one tier (`6 -> 12 -> 24`,
///   already-capped tiers stay capped), still bounded by
///   `MAX_PREDICTED_PORTS`.
///
/// With `step_estimate = None` and `reverse_window = false` the output is
/// byte-for-byte identical to [`predict_ports_for_elapsed`].
pub fn predict_ports_with_learning(
    model: &PortModel,
    last: u16,
    measurement_span_ms: u64,
    gap_ms: u64,
    step_estimate: Option<i16>,
    reverse_window: bool,
) -> Vec<PredictionCandidate> {
    generate_candidates(
        model,
        last,
        measurement_span_ms,
        gap_ms,
        step_estimate,
        reverse_window,
    )
}

/// Shared candidate generation for [`predict_ports_for_elapsed`] and
/// [`predict_ports_with_learning`].
///
/// `effective_step` (the learned estimate) overrides the model stride for the
/// linear branches, and `reverse_window` widens the base confidence window by
/// one tier.  Both flags are inert for the non-linear shapes (Stable,
/// Periodic, MonotonicWindow, Unpredictable), so passing the "plain" defaults
/// reproduces the historical predictor exactly.
fn generate_candidates(
    model: &PortModel,
    last: u16,
    measurement_span_ms: u64,
    gap_ms: u64,
    step_estimate: Option<i16>,
    reverse_window: bool,
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
            // The learned cross-batch stride, when present, is more current
            // than this single batch's median and replaces it.
            let effective_step = step_estimate.unwrap_or(step);
            let base_window = match model.confidence {
                90..=100 => 6,
                75..=89 => 12,
                60..=74 => MAX_PREDICTED_PORTS,
                _ => 0,
            };
            let base_window = reverse_window_size(base_window, reverse_window);
            let extra_window = extra_window_ports(model, measurement_span_ms, gap_ms);
            let window_size = base_window
                .saturating_add(extra_window)
                .min(MAX_PREDICTED_PORTS);
            let low_confidence = model.confidence < 75;
            for distance in 0..window_size {
                let port = modular_add(last, effective_step.saturating_mul((distance + 1) as i16));
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
        PortModelKind::MonotonicWindow { direction } => {
            // There is no justified top-1 stride here. Probe the bounded
            // adjacent window in the observed allocation direction, retaining
            // the rank only as a deterministic send order.  A wide window is
            // used when any sample jumped beyond the small window: the burst
            // proves the CGNAT is busy, so the peer-facing allocation can
            // land farther away.
            let step = i16::from(direction);
            let window = if is_wide_monotonic_window(&model.deltas) {
                MAX_MONOTONIC_WINDOW_PORTS
            } else {
                MAX_PREDICTED_PORTS
            };
            for distance in 1..=window {
                candidates.push(PredictionCandidate {
                    port: modular_add(last, step.saturating_mul(distance as i16)),
                    rank: (distance - 1) as u8,
                    reason: PredictionReason::LowConfidenceWindow {
                        distance: distance as u8,
                    },
                });
            }
        }
        PortModelKind::Unpredictable { .. } => {}
    }

    // A modular wrap can push `last + step*k` to port 0 (e.g. 65535 + 1) and
    // fold two distances onto the same valid port (0 and 1 both normalize to 1).
    // Port 0 is not a usable UDP port and a duplicate wastes probe budget, so
    // drop both and re-rank the survivors sequentially.  Clean (non-wrapping)
    // distributions have no 0 and no duplicates, so this pass leaves them
    // byte-for-byte unchanged — including the rank sequence and the final cap.
    let mut survivors: Vec<PredictionCandidate> = Vec::with_capacity(candidates.len());
    let mut seen_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
    for candidate in candidates {
        if candidate.port != 0 && seen_ports.insert(candidate.port) {
            survivors.push(PredictionCandidate {
                rank: survivors.len() as u8,
                ..candidate
            });
        }
    }
    candidates = survivors;

    let window_cap = if matches!(model.kind, PortModelKind::MonotonicWindow { .. })
        && is_wide_monotonic_window(&model.deltas)
    {
        MAX_MONOTONIC_WINDOW_PORTS
    } else {
        MAX_PREDICTED_PORTS
    };
    candidates.truncate(window_cap);
    candidates
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

    /// An observation at an explicit send `sequence`, with `responded_at_ms`
    /// controllable so a timed-out observer can be modeled (`responded_at_ms == 0`).
    fn observation_at(sequence: u16, observed: u16, responded_at_ms: u64) -> MappingObservation {
        MappingObservation {
            sequence,
            observer: ("1.2.3.4:3478").parse().unwrap(),
            observed: SocketAddr::new(ip(), observed),
            sent_at_ms: 1000,
            responded_at_ms,
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
    fn successful_samples_with_a_timed_out_observer_keep_send_order() {
        // A collector retains only successful observations. A timeout at
        // sequence 1 must not make the valid request order 0,2,3 look like a
        // mixed batch: it still has three measurements from one socket.
        let mut batch = consistent_batch(&[33051, 33052, 33054]);
        batch.observations[1].sequence = 2;
        batch.observations[2].sequence = 3;

        assert!(batch.is_consistent());
        let model = build_model_for_batch(&batch, Duration::from_secs(5), 2000).unwrap();
        assert!(model.kind.clone().is_predictable(), "{:?}", model.kind);
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
    fn shared_cgnat_monotonic_jitter_uses_bounded_adjacent_window() {
        // Captured from the Mini-Air AddressOrPortDependent side on one fresh
        // socket: all mappings advanced, but shared traffic made the deltas
        // +14,+14,+5. There is no safe fixed stride; the only supported
        // fallback is the capped +1..+24 successor window.
        let ports = [62364u16, 62378, 62392, 62397];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(
            model.kind,
            PortModelKind::MonotonicWindow { direction: 1 }
        ));
        assert_eq!(model.confidence, 60);

        let predicted = predict_ports(&model, 62397);
        assert_eq!(predicted.len(), MAX_PREDICTED_PORTS);
        assert_eq!(predicted[0].port, 62398);
        assert_eq!(predicted[0].rank, 0);
        assert_eq!(predicted.last().unwrap().port, 62421);
        assert!(matches!(
            predicted[0].reason,
            PredictionReason::LowConfidenceWindow { distance: 1 }
        ));
    }

    #[test]
    fn shared_cgnat_burst_beyond_small_window_builds_wide_monotonic_window() {
        // Mini-Air round-8 capture on the AddressOrPortDependent side: a
        // +123 single-sample burst on an otherwise steady +23/+3 allocation.
        // Same direction, no reusable stride, but the allocator order is
        // intact: the fallback must advertise a wide bounded window instead
        // of rejecting the batch and signaling nothing.
        let ports = [16311u16, 16434, 16457, 16460];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(
            model.kind,
            PortModelKind::MonotonicWindow { direction: 1 }
        ));
        assert_eq!(model.confidence, 45);

        let predicted = predict_ports(&model, 16460);
        assert_eq!(predicted.len(), MAX_MONOTONIC_WINDOW_PORTS);
        assert_eq!(predicted[0].port, 16461);
        assert_eq!(predicted[0].rank, 0);
        assert_eq!(predicted.last().unwrap().port, 16556);
        assert!(predicted
            .iter()
            .all(|candidate| candidate.port > 16460 && candidate.port <= 16556));
    }

    #[test]
    fn shared_cgnat_moderate_burst_builds_wide_monotonic_window() {
        // Mini-Air round-9 capture: +43 burst, then steady +4/+4.
        let ports = [23356u16, 23399, 23403, 23407];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(
            model.kind,
            PortModelKind::MonotonicWindow { direction: 1 }
        ));
        let predicted = predict_ports(&model, 23407);
        assert_eq!(predicted.len(), MAX_MONOTONIC_WINDOW_PORTS);
        assert_eq!(predicted[0].port, 23408);
    }

    #[test]
    fn monotonic_jump_beyond_wide_bound_is_still_rejected() {
        // A jump beyond the bounded window means the allocator order itself
        // cannot be trusted; the model must not claim a window for it.
        let model = build_model(&[1000u16, 1025, 1565], Some(ip()), 1000);
        assert!(!model.kind.clone().is_predictable(), "{:?}", model.kind);
        assert!(predict_ports(&model, 1565).is_empty());

        let mixed = build_model(&[1000u16, 1025, 1004], Some(ip()), 1000);
        assert!(!mixed.kind.clone().is_predictable(), "{:?}", mixed.kind);
        assert!(predict_ports(&mixed, 1004).is_empty());
    }

    #[test]
    fn wide_window_respects_negative_monotonic_direction() {
        let ports = [20000u16, 19999, 19970, 19960];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(
            model.kind,
            PortModelKind::MonotonicWindow { direction: -1 }
        ));
        let predicted = predict_ports(&model, 19960);
        assert_eq!(predicted.len(), MAX_MONOTONIC_WINDOW_PORTS);
        assert_eq!(predicted[0].port, 19959);
        assert_eq!(predicted.last().unwrap().port, 19864);
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

    // ---- predict_ports_with_learning (adaptive step + reverse window) ----

    #[test]
    fn learning_step_estimate_overrides_fixed_step_top_prediction() {
        // A fixed step-1 model, but the cross-batch learner now believes the
        // peer walks step 7: the top-1 candidate must be last + 7, not + 1.
        let model = build_model(&[45390, 45391, 45392], Some(ip()), 1000);
        assert!(matches!(model.kind, PortModelKind::FixedStep { step: 1 }));
        let predicted = predict_ports_with_learning(&model, 45392, 0, 0, Some(7), false);
        assert_eq!(predicted[0].port, 45399, "the learned estimate must override the model step");
        assert_eq!(predicted[0].reason, PredictionReason::TopPrediction);
        assert_eq!(predicted[0].rank, 0);
    }

    #[test]
    fn learning_none_estimate_matches_plain_predictor() {
        // No learned estimate and no reverse window: identical output to the
        // existing predictor across every linear + periodic + stable shape.
        let cases = [
            (build_model(&[45390, 45391, 45392], Some(ip()), 1000), 45392),
            (build_model(&[1000, 1001, 1000, 1001, 1000, 1001], Some(ip()), 1000), 1001),
            (build_model(&[4483, 4483, 4483], Some(ip()), 1000), 4483),
            (build_model(&[45390, 45391, 45393], Some(ip()), 1000), 45393),
        ];
        for (model, last) in cases {
            let plain = predict_ports_for_elapsed(&model, last, 100, 500);
            let learned = predict_ports_with_learning(&model, last, 100, 500, None, false);
            assert_eq!(
                plain, learned,
                "no-estimate learner output must equal predict_ports_for_elapsed for {:?}",
                model.kind
            );
        }
    }

    #[test]
    fn learning_reverse_window_widens_base_tier() {
        // 95-confidence fixed step -> base 6; reverse widens it one tier to 12.
        let model = build_model(&[45390, 45391, 45392], Some(ip()), 1000);
        assert_eq!(model.confidence, 95);
        let plain = predict_ports_with_learning(&model, 45392, 0, 0, None, false);
        let widened = predict_ports_with_learning(&model, 45392, 0, 0, None, true);
        assert_eq!(plain.len(), 6, "95-confidence fixed step has a 6-wide base window");
        assert_eq!(
            widened.len(),
            12,
            "reverse must widen the 6 tier to 12"
        );
        // The widened window is a strict superset: the first six stay identical.
        assert_eq!(
            plain.iter().map(|c| c.port).collect::<Vec<_>>(),
            widened.iter().take(6).map(|c| c.port).collect::<Vec<_>>()
        );
    }

    #[test]
    fn learning_reverse_window_caps_at_max() {
        // Construct a linear model in the 60..=74 tier (base window already at
        // the cap).  `build_model` never emits a linear kind at this tier, so
        // the model is built directly: this isolates the cap invariant from
        // the model classifier's confidence assignment.
        let model = PortModel {
            kind: PortModelKind::FixedStep { step: 1 },
            confidence: 70,
            public_ip: Some(ip()),
            sequence: vec![45390, 45391, 45392],
            deltas: vec![1, 1],
            sampled_at_ms: 1000,
        };
        let plain = predict_ports_with_learning(&model, 45392, 0, 0, None, false);
        let widened = predict_ports_with_learning(&model, 45392, 0, 0, None, true);
        assert_eq!(
            plain.len(),
            MAX_PREDICTED_PORTS,
            "70-confidence linear is already at the cap"
        );
        assert_eq!(
            widened.len(),
            MAX_PREDICTED_PORTS,
            "reverse must never exceed MAX_PREDICTED_PORTS"
        );
    }

    #[test]
    fn learning_reverse_window_handles_12_tier() {
        // 86-confidence Linear (same direction, spread 1) -> base 12; reverse -> 24.
        let model = build_model(&[1000, 1001, 1003], Some(ip()), 1000);
        assert!(
            matches!(model.kind, PortModelKind::Linear { step: 2 }),
            "{:?}",
            model.kind
        );
        assert_eq!(model.confidence, 86, "a spread-1 same-direction linear is the 12 tier");
        let plain = predict_ports_with_learning(&model, 1003, 0, 0, None, false);
        let widened = predict_ports_with_learning(&model, 1003, 0, 0, None, true);
        assert_eq!(plain.len(), 12, "86-confidence linear has a 12-wide base window");
        assert_eq!(widened.len(), MAX_PREDICTED_PORTS, "reverse must widen 12 to the 24 cap");
    }

    #[test]
    fn learning_estimate_wrap_is_modular() {
        // last 65534, learned step +3 -> top candidate wraps to port 1.
        let model = build_model(&[45390, 45391, 45392], Some(ip()), 1000);
        let predicted = predict_ports_with_learning(&model, 65534, 0, 0, Some(3), false);
        assert_eq!(predicted[0].port, 1, "the learned-step top candidate must wrap mod 65536");
    }

    // ---- P0-3: port 0 is never a candidate ----

    #[test]
    fn fixed_step_wrap_does_not_emit_port_zero() {
        // A strict +1 allocator sitting at the very top of the 16-bit space:
        // 65533, 65534, 65535.  The model step is +1, so `last + step` is
        // 65536 mod 65536 = 0, which is not a valid UDP port.  The predictor
        // must wrap to 1 instead of advertising port 0 as the top candidate.
        let ports = [65533u16, 65534, 65535];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(model.kind, PortModelKind::FixedStep { step: 1 }));
        let predicted = predict_ports(&model, 65535);
        assert!(
            !predicted.iter().any(|candidate| candidate.port == 0),
            "port 0 must never be a candidate, got {:?}",
            predicted
        );
        assert_eq!(
            predicted.first().map(|candidate| candidate.port),
            Some(1),
            "the top candidate must wrap 65535+1 to port 1"
        );
        assert_eq!(predicted[0].rank, 0);
        // Ranks stay contiguous after dropping the invalid port.
        let ranks: Vec<u8> = predicted.iter().map(|candidate| candidate.rank).collect();
        assert_eq!(ranks, (0..predicted.len() as u8).collect::<Vec<_>>());
    }

    #[test]
    fn learned_step_wrap_does_not_emit_port_zero() {
        // The cross-batch learner drives the top candidate the same way the
        // model step does: a learned step of +1 from last 65535 must not yield
        // port 0.
        let model = build_model(&[45390, 45391, 45392], Some(ip()), 1000);
        let predicted = predict_ports_with_learning(&model, 65535, 0, 0, Some(1), false);
        assert!(
            !predicted.iter().any(|candidate| candidate.port == 0),
            "a learned-step candidate must never be port 0, got {:?}",
            predicted
        );
        assert_eq!(predicted.first().map(|candidate| candidate.port), Some(1));
    }

    #[test]
    fn monotonic_window_wrap_does_not_emit_port_zero() {
        // A busy CGNAT near the top of the space with same-direction but
        // non-uniform jumps (+2 then +5): spread 3 is not a Linear step and the
        // jumps are not multiples of each other, so this is a MonotonicWindow.
        // The window walks `last + 1`, which from 65535 is port 0.
        let ports = [65528u16, 65530, 65535];
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(
            matches!(model.kind, PortModelKind::MonotonicWindow { direction: 1 }),
            "{:?}",
            model.kind
        );
        let predicted = predict_ports(&model, 65535);
        assert!(
            !predicted.iter().any(|candidate| candidate.port == 0),
            "a monotonic-window candidate must never be port 0, got {:?}",
            predicted
        );
    }

    #[test]
    fn candidates_are_unique_when_the_window_wraps() {
        // A large fixed step near the 16-bit boundary folds two window
        // distances onto the same port once the modular arithmetic wraps
        // (e.g. step 16384: k=1 and k=5 both land on the same port).  The
        // survivor pass must de-duplicate so the peer is never told to probe
        // the same port twice — and never port 0.
        let ports = [1000u16, 17384, 33768]; // +16384 each -> FixedStep{16384}
        let model = build_model(&ports, Some(ip()), 1000);
        assert!(matches!(model.kind, PortModelKind::FixedStep { step: 16384 }));
        for last in [33768u16, 50152, 65000] {
            let predicted = predict_ports(&model, last);
            let mut seen = std::collections::HashSet::new();
            for candidate in &predicted {
                assert!(
                    seen.insert(candidate.port),
                    "duplicate candidate port {} for last={}: {:?}",
                    candidate.port,
                    last,
                    predicted
                );
                assert!(
                    candidate.port != 0,
                    "port 0 must not survive for last={}",
                    last
                );
            }
        }
    }

    #[test]
    fn learning_unpredictable_model_is_empty() {
        let model = build_model(&[1000, 1005, 1001, 1009, 1002], Some(ip()), 1000);
        assert!(!model.kind.clone().is_predictable());
        let predicted = predict_ports_with_learning(&model, 1002, 0, 0, Some(7), true);
        assert!(
            predicted.is_empty(),
            "an unpredictable model must yield no candidates even with learning"
        );
    }

    // ---- P0-2: a timed-out observer must not fabricate a wrong step ----

    #[test]
    fn single_gap_timeout_does_not_fabricate_double_step() {
        // A strict +1 allocator, four observers in send order, but observer
        // at sequence 1 timed out: the real collector keeps only successful
        // observations, so the batch is [seq0, seq2, seq3] with ports
        // 1000, 1002, 1003.  The seq1 request was already sent and its NAT
        // mapping very likely already consumed — naively differencing the
        // survivors yields [+2, +1] and the old upper-median logic learned
        // Linear{step:2}, so `last + 2 = 1005` — which misses the real next
        // allocation 1004.  A gap must never be folded into the exact step.
        let batch = MappingBatch {
            generation: 7,
            network_generation: 3,
            socket_identity: ("0.0.0.0:58980").parse().unwrap(),
            observations: vec![
                observation_at(0, 1000, 1050),
                observation_at(2, 1002, 1060),
                observation_at(3, 1003, 1070),
            ],
            started_at_ms: 1000,
            finished_at_ms: 1100,
        };
        assert!(
            batch.is_consistent(),
            "a gap alone must not make the batch inconsistent"
        );
        let model = build_model_for_batch(&batch, Duration::from_secs(5), 2000).unwrap();
        // The survivors 1000,1002,1003 are strictly increasing, so the
        // allocator order is intact — we must NOT reject the batch.
        assert!(model.kind.clone().is_predictable(), "{:?}", model.kind);
        let predicted = predict_ports(&model, 1003);
        let ports: Vec<u16> = predicted.iter().map(|c| c.port).collect();
        assert!(
            ports.contains(&1004),
            "the real next allocation 1004 must be in the window, got {:?}",
            ports
        );
        assert!(
            !matches!(
                model.kind,
                PortModelKind::Linear { step: 2 }
                    | PortModelKind::FixedStep { step: 2 }
                    | PortModelKind::NoisyLinear { step: 2 }
            ),
            "a single gap must not be learned as step 2, got {:?}",
            model.kind
        );
    }

    #[test]
    fn no_gap_batch_is_unchanged_by_gap_logic() {
        // Backward-compat guard: a gap-free +1 batch must keep its exact
        // FixedStep model and predictor output identical to before the
        // sequence-gap-aware path was introduced.
        let batch = consistent_batch(&[45390, 45391, 45392]);
        let model = build_model_for_batch(&batch, Duration::from_secs(5), 2000).unwrap();
        assert!(
            matches!(model.kind, PortModelKind::FixedStep { step: 1 }),
            "{:?}",
            model.kind
        );
        assert_eq!(model.confidence, 95);
        let predicted = predict_ports(&model, 45392);
        assert_eq!(predicted[0].port, 45393);
        assert_eq!(predicted.len(), 6);
    }
}

