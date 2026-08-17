//! Adaptive prediction enhancements for fresh-mapping models.
//!
//! This is a semantic 1:1 migration of the two stateful helpers validated in
//! `scripts/punch-research/predict.py` (S1.2/S1.3): a dual-channel EWMA step
//! learner and a reverse-allocation pattern detector.  Both are per-public-IP
//! state: the daemon resets them when the local public IP or network
//! generation changes, because a different allocator instance means none of
//! the learned stride or direction is transferable.
//!
//! Neither type is a model in its own right — they only refine the stride a
//! [`crate::mapping::PortModel`] already identified and widen the candidate
//! window when the peer's mappings are walking backwards.  See
//! [`crate::mapping::predict_ports_with_learning`] for the consumption point.

use std::collections::VecDeque;

/// Rolling window (in observations) over which the diff channel computes its
/// mode, mirroring `StepLearner(mode_window=8)`.
const DIFF_MODE_WINDOW: usize = 8;

/// Bounded ring of raw positive diffs fed to the mode + EWMA (maxlen 32 in the
/// reference implementation).
const DIFF_BUFFER: usize = 32;

/// Bounded ring of observed peer ports kept for direction detection (maxlen 32).
const PORT_BUFFER: usize = 32;

/// The direction a peer's fresh mappings are walking.
///
/// Detected from the sign of the (wrap-normalized) differences between
/// consecutive observed ports over a rolling window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectionPattern {
    /// Allocations advance (new port > old port) or the sample is too small to
    /// tell: the default, and the safe assumption.
    #[default]
    Forward,
    /// Allocations walk backwards (new port < old port, i.e. the peer's
    /// allocator is recycling down) — the window should be widened.
    Reverse,
    /// Signs are mixed — no single direction is trustworthy.
    Mixed,
}

impl DirectionPattern {
    /// Lower-case label for structured logs and direct events.
    pub fn as_str(self) -> &'static str {
        match self {
            DirectionPattern::Forward => "forward",
            DirectionPattern::Reverse => "reverse",
            DirectionPattern::Mixed => "mixed",
        }
    }
}

/// Learns the peer's fresh-mapping stride across batches.
///
/// Two channels are fused (mirroring the reference `StepLearner`):
/// - channel A: the peer's advertised stride (a single authoritative value),
///   updated with a high weight;
/// - channel B: the peer's observed per-request port deltas, first reduced to
///   their rolling-window mode (noise-resistant) then EWMA-smoothed with a
///   lower weight.
///
/// `estimate = ALPHA_ADVERT * A + ALPHA_DIFF * B`, or the single known channel
/// when only one has observations.  The estimate is signed — the observed-diff
/// channel learns a reverse (negative) allocator as well as a forward one — and
/// only a zero consensus is suppressed.  It counts a revision when the value
/// actually changes.
#[derive(Debug)]
pub struct StepLearner {
    /// Channel A smoothed value (peer-advertised stride).
    advert_est: Option<f64>,
    /// Channel B smoothed value (observed-diff mode).
    diff_est: Option<f64>,
    /// Bounded ring of raw observed diffs (the noise source for B); zero diffs
    /// are filtered out at the source, both positive and negative are kept.
    diffs: VecDeque<i16>,
    /// Current fused estimate (signed), or `None` before any observation.
    estimate: Option<i16>,
    /// Running maximum of the diff-channel mode coverage (0.0..=1.0).
    confidence: f64,
    /// Number of times the fused estimate changed (learning trajectory).
    revision_count: u32,
}

impl Default for StepLearner {
    fn default() -> Self {
        Self::new()
    }
}

impl StepLearner {
    /// Weight of the peer-advertised channel (authoritative).
    pub const ALPHA_ADVERT: f64 = 0.6;
    /// Weight of the observed-diff channel.
    pub const ALPHA_DIFF: f64 = 0.4;

    /// A learner with no observations yet.
    pub fn new() -> Self {
        Self {
            advert_est: None,
            diff_est: None,
            diffs: VecDeque::with_capacity(DIFF_BUFFER),
            estimate: None,
            confidence: 0.0,
            revision_count: 0,
        }
    }

    /// Clear all learned state (public IP / network generation changed).
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Fold one observed signed port delta (the step the peer's allocator moved
    /// by between two consecutive fresh mappings).
    ///
    /// A zero delta carries no stride information (an unchanged port) and is
    /// ignored; positive and negative deltas are both kept so the learner tracks
    /// a reverse (downward) allocator as well as a forward one.  The raw diff is
    /// buffered, then the last `DIFF_MODE_WINDOW` diffs are reduced to their
    /// (noise-resistant) mode, which EWMA-smooths the diff channel before the
    /// two channels are fused.
    pub fn observe_diff(&mut self, diff: i16) {
        if diff == 0 {
            return;
        }
        self.diffs.push_back(diff);
        if self.diffs.len() > DIFF_BUFFER {
            self.diffs.pop_front();
        }
        let start = self.diffs.len().saturating_sub(DIFF_MODE_WINDOW);
        let window: Vec<i16> = self.diffs.iter().skip(start).copied().collect();
        let Some((mode, coverage)) = self.mode(&window) else {
            return;
        };
        let smoothed = match self.diff_est {
            None => mode as f64,
            Some(prev) => Self::ALPHA_DIFF * mode as f64 + (1.0 - Self::ALPHA_DIFF) * prev,
        };
        self.diff_est = Some(smoothed);
        self.recompute(Some(coverage));
    }

    /// Fold one peer-advertised stride value.  Non-positive values are
    /// ignored.  The advertised channel is the authoritative one, so it is
    /// EWMA-smoothed with the higher `ALPHA_ADVERT` weight.
    pub fn observe_advertised(&mut self, step: i16) {
        if step <= 0 {
            return;
        }
        let smoothed = match self.advert_est {
            None => step as f64,
            Some(prev) => Self::ALPHA_ADVERT * step as f64 + (1.0 - Self::ALPHA_ADVERT) * prev,
        };
        self.advert_est = Some(smoothed);
        self.recompute(None);
    }

    /// The current fused stride estimate (signed), or `None` before any
    /// observation.  `Some(0)` means the recent diffs carried no direction
    /// consensus; callers treat that as "no useful stride".
    pub fn estimate(&self) -> Option<i16> {
        self.estimate
    }

    /// Confidence in the estimate: the running maximum diff-channel mode
    /// coverage, in `0.0..=1.0`.
    pub fn confidence(&self) -> f64 {
        self.confidence
    }

    /// How many times the fused estimate has changed (0 = no change yet).
    pub fn revision_count(&self) -> u32 {
        self.revision_count
    }

    /// The mode of the last `DIFF_MODE_WINDOW` values with its coverage.
    ///
    /// Returns `(mode, count/len)`.  On a tie the earlier-observed value wins:
    /// diffs are pushed in send order, so the first value to reach the max
    /// count is kept, matching the reference `Counter.most_common(1)` order.
    fn mode(&self, values: &[i16]) -> Option<(i16, f64)> {
        let (mode, count) = values.iter().fold(None, |best: Option<(i16, usize)>, &value| {
            let count = values.iter().filter(|other| **other == value).count();
            match best {
                None => Some((value, count)),
                Some((_, candidate_count)) if count > candidate_count => Some((value, count)),
                _ => best,
            }
        })?;
        Some((mode, count as f64 / values.len() as f64))
    }

    /// Recompute the fused estimate from the two channel values and advance
    /// the revision counter + confidence.  The estimate is signed (a reverse
    /// allocator learns a negative stride); a near-zero fused value is rounded
    /// to 0 rather than clamped up to a stray positive stride.
    fn recompute(&mut self, diff_cov: Option<f64>) {
        let (a, b) = (self.advert_est, self.diff_est);
        let est = match (a, b) {
            (Some(a), Some(b)) => Some(Self::ALPHA_ADVERT * a + Self::ALPHA_DIFF * b),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let Some(est) = est else {
            return;
        };
        let new = est.round() as i16;
        if self.estimate != Some(new) {
            self.revision_count += 1;
        }
        self.estimate = Some(new);
        if let Some(cov) = diff_cov {
            self.confidence = self.confidence.max(cov).min(1.0);
        }
    }
}

/// Detects whether the peer's fresh mappings are advancing, reversing or
/// oscillating, so the predictor can widen its window on reverse allocation.
///
/// Mirrors the reference `ReverseDetector`: differences between consecutive
/// observed ports are wrap-normalized into `[-32768, 32767]`, their signs are
/// reduced to a rolling window, and the majority decides the pattern.
#[derive(Debug)]
pub struct ReverseDetector {
    /// Rolling window of signs inspected (8 in the reference).
    window: usize,
    /// Bounded ring of the most recently observed peer ports.
    ports: VecDeque<u16>,
    /// Current classification.
    pattern: DirectionPattern,
}

impl Default for ReverseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ReverseDetector {
    /// A detector with no observations yet (defaults to [`DirectionPattern::Forward`]).
    pub fn new() -> Self {
        Self {
            window: DIFF_MODE_WINDOW,
            ports: VecDeque::with_capacity(PORT_BUFFER),
            pattern: DirectionPattern::Forward,
        }
    }

    /// Clear all observed ports and return to the default `Forward` pattern.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Record one observed peer port (in allocation order) and reclassify.
    ///
    /// The classification is recomputed from the sign of every consecutive
    /// (wrap-normalized) difference over the stored ports, restricted to the
    /// last `window` signs.  Fewer than three ports is not enough evidence, so
    /// the pattern holds at its default `Forward`.
    pub fn observe_port(&mut self, port: u16) {
        self.ports.push_back(port);
        if self.ports.len() > PORT_BUFFER {
            self.ports.pop_front();
        }
        if self.ports.len() < 3 {
            return;
        }
        let ports: Vec<u16> = self.ports.iter().copied().collect();
        let mut signs: Vec<i8> = Vec::with_capacity(ports.len() - 1);
        let mut prev = ports[0];
        for current in ports.iter().skip(1) {
            let difference = crate::mapping::modular_difference(prev, *current);
            if difference != 0 {
                signs.push(if difference > 0 { 1 } else { -1 });
            }
            prev = *current;
        }
        if signs.is_empty() {
            self.pattern = DirectionPattern::Forward;
            return;
        }
        let recent = &signs[signs.len().saturating_sub(self.window)..];
        let pos = recent.iter().filter(|&&sign| sign > 0).count();
        let neg = recent.iter().filter(|&&sign| sign < 0).count();
        self.pattern = if pos > 0 && neg > 0 {
            DirectionPattern::Mixed
        } else if neg > 0 && neg >= pos {
            DirectionPattern::Reverse
        } else {
            DirectionPattern::Forward
        };
    }

    /// The current direction classification.
    pub fn pattern(&self) -> DirectionPattern {
        self.pattern
    }

    /// Suggest a window multiplier for the predictor: one larger than `w`
    /// when the peer is allocating in reverse (to cover the backwards drift),
    /// otherwise `w` unchanged.
    pub fn suggest_window(&self, w: u8) -> u8 {
        if self.pattern == DirectionPattern::Reverse {
            w.saturating_add(1)
        } else {
            w
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- StepLearner ----

    #[test]
    fn diff_only_mode_three() {
        let mut learner = StepLearner::new();
        for _ in 0..3 {
            learner.observe_diff(3);
        }
        assert_eq!(learner.estimate(), Some(3), "three identical diffs must pin the mode to 3");
        assert!(learner.confidence() > 0.0 && learner.confidence() <= 1.0);
        assert!(learner.revision_count() >= 1, "the first estimate change is a revision");
    }

    #[test]
    fn advertised_only() {
        let mut learner = StepLearner::new();
        learner.observe_advertised(5);
        assert_eq!(learner.estimate(), Some(5), "a lone advertised channel sets the estimate");
    }

    #[test]
    fn dual_channel_fuses_to_four() {
        let mut learner = StepLearner::new();
        learner.observe_advertised(5);
        learner.observe_diff(3);
        // 0.6*5 + 0.4*3 = 4.2 -> round 4 (advertised dominates but does not
        // fully overwrite the diff channel).
        assert_eq!(learner.estimate(), Some(4));
    }

    #[test]
    fn ewma_advertised_progression_takes_effect() {
        let mut learner = StepLearner::new();
        learner.observe_advertised(2);
        assert_eq!(learner.estimate(), Some(2));
        // Second observation pulls the running mean toward the new value;
        // this only changes if the ALPHA_ADVERT weighting actually applies.
        learner.observe_advertised(8);
        // 0.6*8 + 0.4*2 = 5.6 -> 6, distinct from a naive last-write-wins (8)
        // and from ignoring the weight (2).
        assert_eq!(learner.estimate(), Some(6), "EWMA must blend, not overwrite");
        assert_eq!(learner.revision_count(), 2, "each distinct change is one revision");
    }

    #[test]
    fn ewma_diff_progression_takes_effect() {
        let mut learner = StepLearner::new();
        learner.observe_diff(1);
        assert_eq!(learner.estimate(), Some(1));
        // A burst of a larger value then dominates the window mode, but the
        // EWMA (ALPHA_DIFF = 0.4) lags behind the mode rather than jumping to
        // it: over [1,5,5,5,5] the smoothed diff ends at ~4.14, so the estimate
        // is 4.  A last-write-wins or raw-mode learner would yield 5.
        for _ in 0..4 {
            learner.observe_diff(5);
        }
        assert_eq!(
            learner.estimate(),
            Some(4),
            "diff EWMA must blend toward the new dominant mode, not snap to it"
        );
    }

    #[test]
    fn nonpositive_diff_is_ignored() {
        let mut learner = StepLearner::new();
        learner.observe_diff(3);
        let before = (learner.estimate(), learner.revision_count());
        learner.observe_diff(0);
        assert_eq!(
            (learner.estimate(), learner.revision_count()),
            before,
            "zero diffs carry no stride information and must not touch the estimate"
        );
    }

    #[test]
    fn learner_learns_negative_stride() {
        // P0-1: the learner must track a reverse allocator.  Three identical
        // -1 diffs pin a signed stride of -1 (the old positive-only learner
        // dropped these and never learned the reversal).
        let mut learner = StepLearner::new();
        for _ in 0..3 {
            learner.observe_diff(-1);
        }
        assert_eq!(
            learner.estimate(),
            Some(-1),
            "identical negative diffs must pin a negative stride"
        );
    }

    #[test]
    fn learner_sign_conflict_does_not_advertise_a_stray_step() {
        // P0-1: if the recent diffs oscillate around zero (the allocator just
        // reversed direction within the mode window), the fused estimate must
        // not advertise a confidently-wrong single sign.  A near-zero / no-
        // consensus estimate is acceptable; what is not acceptable is a stale
        // one-sign stride overriding the current batch — but that guard lives
        // in the predictor.  Here we only assert the learner stops forcing >= 1.
        let mut learner = StepLearner::new();
        for diff in [1, 1, 1, -1, -1, -1, -1] {
            learner.observe_diff(diff);
        }
        // The dominant mode is -1, so the estimate must land negative or at
        // least not be clamped up to a positive stride.
        assert!(
            learner.estimate().map_or(true, |e| e <= 0),
            "a reversing batch must not yield a positive clamped stride, got {:?}",
            learner.estimate()
        );
    }

    #[test]
    fn nonpositive_advertised_is_ignored() {
        let mut learner = StepLearner::new();
        learner.observe_advertised(5);
        let before = (learner.estimate(), learner.revision_count());
        learner.observe_advertised(0);
        learner.observe_advertised(-1);
        assert_eq!(
            (learner.estimate(), learner.revision_count()),
            before,
            "zero/negative advertised steps must not touch the estimate"
        );
    }

    #[test]
    fn mode_resists_noise() {
        let mut learner = StepLearner::new();
        for diff in [1, 1, 10, 1] {
            learner.observe_diff(diff);
        }
        // Mode over [1,1,10,1] is 1 (coverage 0.75) -> estimate 1 (>=1 clamp
        // also holds).  Even a single EWMA pass from the first mode keeps it
        // in {1,2}.
        assert!(
            matches!(learner.estimate(), Some(1) | Some(2)),
            "the mode must dominate the noisy 10, got {:?}",
            learner.estimate()
        );
    }

    #[test]
    fn revision_count_only_changes_when_estimate_moves() {
        let mut learner = StepLearner::new();
        learner.observe_diff(3);
        let after_first = learner.revision_count();
        // Same value again: no new estimate, so no new revision.
        learner.observe_diff(3);
        assert_eq!(
            learner.revision_count(),
            after_first,
            "re-observing the same estimate must not bump the revision"
        );
    }

    #[test]
    fn reset_clears_learner() {
        let mut learner = StepLearner::new();
        learner.observe_diff(3);
        assert!(learner.estimate().is_some());
        learner.reset();
        assert_eq!(learner.estimate(), None);
        assert_eq!(learner.revision_count(), 0);
        assert_eq!(learner.confidence(), 0.0);
    }

    #[test]
    fn golden_p2_matches_predict_py() {
        // Mirrors predict.py P2: diff [3,3,4,3] then advertised [5,5].
        let mut learner = StepLearner::new();
        for diff in [3, 3, 4, 3] {
            learner.observe_diff(diff);
        }
        assert_eq!(learner.estimate(), Some(3));
        learner.observe_advertised(5);
        learner.observe_advertised(5);
        // 0.6*5 + 0.4*3 = 4.2 -> 4.
        assert_eq!(learner.estimate(), Some(4));
    }

    // ---- ReverseDetector ----

    #[test]
    fn forward_sequence() {
        let mut detector = ReverseDetector::new();
        for port in [5000u16, 5003, 5006, 5009] {
            detector.observe_port(port);
        }
        assert_eq!(detector.pattern(), DirectionPattern::Forward);
        assert_eq!(detector.suggest_window(2), 2, "forward must not widen the window");
    }

    #[test]
    fn reverse_sequence() {
        let mut detector = ReverseDetector::new();
        for port in [5009u16, 5006, 5003, 5000] {
            detector.observe_port(port);
        }
        assert_eq!(detector.pattern(), DirectionPattern::Reverse);
        assert_eq!(detector.suggest_window(2), 3, "reverse must widen the window by one");
    }

    #[test]
    fn mixed_sequence() {
        let mut detector = ReverseDetector::new();
        for port in [5000u16, 5003, 5000, 5003] {
            detector.observe_port(port);
        }
        assert_eq!(detector.pattern(), DirectionPattern::Mixed);
        assert_eq!(detector.suggest_window(2), 2, "mixed must keep the window unchanged");
    }

    #[test]
    fn wrap_normalizes_forward() {
        // 65534 -> 65535 (+1) -> 1 (+2 across the 16-bit wrap): all positive.
        let mut detector = ReverseDetector::new();
        for port in [65534u16, 65535, 1] {
            detector.observe_port(port);
        }
        assert_eq!(
            detector.pattern(),
            DirectionPattern::Forward,
            "65535 -> 1 is a +2 forward step, not a reverse"
        );
    }

    #[test]
    fn wrap_normalizes_reverse() {
        // 3 -> 1 (-2) -> 65535 (-2 across the wrap): all negative.
        let mut detector = ReverseDetector::new();
        for port in [3u16, 1, 65535] {
            detector.observe_port(port);
        }
        assert_eq!(
            detector.pattern(),
            DirectionPattern::Reverse,
            "1 -> 65535 is a -2 reverse step, not a forward"
        );
    }

    #[test]
    fn fewer_than_three_observes_stay_forward() {
        let mut detector = ReverseDetector::new();
        detector.observe_port(1000);
        assert_eq!(detector.pattern(), DirectionPattern::Forward);
        detector.observe_port(990); // a single decrease is not yet "reverse"
        assert_eq!(
            detector.pattern(),
            DirectionPattern::Forward,
            "with fewer than three ports the default holds"
        );
    }

    #[test]
    fn reset_recovers_default() {
        let mut detector = ReverseDetector::new();
        for port in [5009u16, 5006, 5003, 5000] {
            detector.observe_port(port);
        }
        assert_eq!(detector.pattern(), DirectionPattern::Reverse);
        detector.reset();
        assert_eq!(detector.pattern(), DirectionPattern::Forward);
        assert_eq!(detector.suggest_window(2), 2);
    }
}
