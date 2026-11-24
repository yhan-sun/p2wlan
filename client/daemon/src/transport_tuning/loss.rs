use crate::config::FecMode;
use std::time::Duration;
use tokio::time::Instant;

const HOLD: Duration = Duration::from_millis(250);
const REPORT_PERIOD: Duration = Duration::from_millis(250);
const SAMPLE: u32 = 64;

#[derive(Default)]
pub(crate) struct Loss {
    start: u64,
    top: Option<u64>,
    seen: u128,
    expected: u32,
    missing: u32,
    estimate: u16,
    report_sent: Option<(Instant, u16)>,
    outgoing: usize,
    changed_at: Option<Instant>,
    feedback_at: Option<Instant>,
}

impl Loss {
    /// Finalize only counters that have moved past a 32-packet reorder guard.
    pub(crate) fn observe(&mut self, counter: u64, now: Instant) -> Option<u16> {
        let Some(top) = self.top else {
            self.start = counter;
            self.top = Some(counter);
            self.seen = 1;
            return None;
        };
        if let Some(offset) = top.checked_sub(counter) {
            if offset < 32 {
                self.seen |= 1u128 << offset;
            }
            return None;
        }
        let steps = (counter - top).min(128) as u32;
        let lower = self.start.max(top.saturating_sub(31));
        let finalized = counter
            .checked_sub(32)
            .and_then(|end| end.checked_sub(lower))
            .map_or(0, |span| {
                span.saturating_add(1).min(u64::from(steps)) as u32
            });
        let expired = (self.seen >> (32 - steps.min(32))).count_ones();
        self.expected += finalized;
        self.missing += finalized.saturating_sub(expired);
        self.top = Some(counter);
        self.seen = (self.seen.checked_shl(steps).unwrap_or(0) | 1) & ((1u128 << 32) - 1);
        if self.expected < SAMPLE {
            return None;
        }
        let sample = (self.missing * 10_000 / self.expected) as u16;
        self.estimate = if self.report_sent.is_none() {
            sample
        } else {
            ((u32::from(self.estimate) + 3 * u32::from(sample)) / 4) as u16
        };
        self.expected = 0;
        self.missing = 0;
        let previous = self.report_sent.map_or(0, |(_, value)| value);
        let repeat = self
            .report_sent
            .is_none_or(|(sent, _)| now.duration_since(sent) >= REPORT_PERIOD);
        let report = self.estimate >= 80 || previous >= 80;
        if report && repeat {
            self.report_sent = Some((now, self.estimate));
            Some(self.estimate)
        } else {
            None
        }
    }

    pub(crate) fn receive_feedback(&mut self, loss_bp: u16, now: Instant) {
        self.feedback_at = Some(now);
        let mode = match self.outgoing {
            0 if loss_bp >= 100 => {
                if loss_bp > 500 {
                    3
                } else {
                    1
                }
            }
            1 if loss_bp > 500 => 3,
            1 if loss_bp < 70 => 0,
            3 if loss_bp < 70 => 0,
            3 if loss_bp < 400 => 1,
            mode => mode,
        };
        if self.outgoing != mode
            && self
                .changed_at
                .is_none_or(|when| now.duration_since(when) >= HOLD)
        {
            self.outgoing = mode;
            self.changed_at = Some(now);
        }
    }

    pub(crate) fn rows(&self, mode: FecMode, now: Instant) -> usize {
        match mode {
            FecMode::Light => 1,
            FecMode::Strong => 3,
            FecMode::Auto
                if self
                    .feedback_at
                    .is_some_and(|when| now.duration_since(when) < Duration::from_secs(6)) =>
            {
                self.outgoing
            }
            FecMode::Auto | FecMode::Off => 0,
        }
    }

    pub(crate) fn estimate(&self) -> f64 {
        f64::from(self.estimate) / 10_000.0
    }
}
