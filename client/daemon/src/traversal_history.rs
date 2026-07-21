//! Anonymous local NAT traversal history.
//!
//! This file intentionally stores only source-level aggregate counters
//! (`predicted`, `stun_observed`, `peer_reflexive`, ...). It does not persist
//! public IPs, SSIDs, BSSIDs, router model names, or peer identifiers.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::peer::CandidatePairSource;

pub const TRAVERSAL_HISTORY_FILE_NAME: &str = "traversal-history.json";
const TRAVERSAL_HISTORY_VERSION: u8 = 1;
const MAX_HISTORY_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const SHORT_COOLDOWN_MS: u64 = 60 * 1000;
const LONG_COOLDOWN_MS: u64 = 5 * 60 * 1000;

/// Persistent anonymous traversal history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraversalHistory {
    pub version: u8,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub sources: BTreeMap<String, TraversalSourceHistory>,
}

impl Default for TraversalHistory {
    fn default() -> Self {
        Self {
            version: TRAVERSAL_HISTORY_VERSION,
            updated_at_ms: now_ms(),
            sources: BTreeMap::new(),
        }
    }
}

impl TraversalHistory {
    pub fn load(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        let Ok(content) = fs::read_to_string(path) else {
            return Self::default();
        };
        let Ok(mut history) = serde_json::from_str::<Self>(&content) else {
            return Self::default();
        };
        history.version = TRAVERSAL_HISTORY_VERSION;
        history.prune_expired(now_ms());
        history
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_vec_pretty(self)?;
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, content)?;
        fs::rename(tmp_path, path)
    }

    pub fn record_success(&mut self, source: CandidatePairSource) {
        if !source.is_persisted_history_source() {
            return;
        }
        let now = now_ms();
        self.updated_at_ms = now;
        let entry = self.entry_mut(source);
        entry.success_count = entry.success_count.saturating_add(1);
        entry.consecutive_failures = 0;
        entry.last_success_at_ms = Some(now);
        entry.cooldown_until_ms = None;
    }

    pub fn record_failure(&mut self, source: CandidatePairSource) {
        if !source.is_persisted_history_source() {
            return;
        }
        let now = now_ms();
        self.updated_at_ms = now;
        let entry = self.entry_mut(source);
        entry.failure_count = entry.failure_count.saturating_add(1);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_failure_at_ms = Some(now);
        entry.cooldown_until_ms = cooldown_until(now, entry.consecutive_failures);
    }

    pub fn source(&self, source: CandidatePairSource) -> Option<&TraversalSourceHistory> {
        self.sources.get(source.history_label())
    }

    pub fn source_success_rate_per_mille(&self, source: CandidatePairSource) -> Option<u16> {
        self.source(source)
            .and_then(TraversalSourceHistory::success_rate_per_mille)
    }

    pub fn source_in_cooldown(&self, source: CandidatePairSource) -> bool {
        let now = now_ms();
        self.source(source)
            .and_then(|entry| entry.cooldown_until_ms)
            .is_some_and(|until| until > now)
    }

    pub fn prune_expired(&mut self, now_ms: u64) {
        self.sources.retain(|_, entry| {
            let latest = entry
                .last_success_at_ms
                .into_iter()
                .chain(entry.last_failure_at_ms)
                .max()
                .unwrap_or(now_ms);
            now_ms.saturating_sub(latest) <= MAX_HISTORY_AGE_MS
        });
    }

    pub fn diagnostics(&self) -> TraversalHistoryDiagnostics {
        let now = now_ms();
        TraversalHistoryDiagnostics {
            sources: self
                .sources
                .iter()
                .map(|(source, entry)| TraversalSourceHistoryDiagnostics {
                    source: source.clone(),
                    success_count: entry.success_count,
                    failure_count: entry.failure_count,
                    consecutive_failures: entry.consecutive_failures,
                    success_rate_per_mille: entry.success_rate_per_mille(),
                    last_success_age_ms: entry.last_success_at_ms.map(|at| now.saturating_sub(at)),
                    last_failure_age_ms: entry.last_failure_at_ms.map(|at| now.saturating_sub(at)),
                    cooldown_remaining_ms: entry
                        .cooldown_until_ms
                        .map(|until| until.saturating_sub(now))
                        .filter(|remaining| *remaining > 0),
                })
                .collect(),
        }
    }

    fn entry_mut(&mut self, source: CandidatePairSource) -> &mut TraversalSourceHistory {
        self.sources
            .entry(source.history_label().to_string())
            .or_default()
    }
}

/// Aggregate history for one candidate source.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraversalSourceHistory {
    #[serde(default)]
    pub success_count: u64,
    #[serde(default)]
    pub failure_count: u64,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub last_success_at_ms: Option<u64>,
    #[serde(default)]
    pub last_failure_at_ms: Option<u64>,
    #[serde(default)]
    pub cooldown_until_ms: Option<u64>,
}

impl TraversalSourceHistory {
    pub fn success_rate_per_mille(&self) -> Option<u16> {
        let total = self.success_count.saturating_add(self.failure_count);
        if total == 0 {
            return None;
        }
        Some(((self.success_count.saturating_mul(1000)) / total).min(1000) as u16)
    }
}

/// Serializable diagnostics for local traversal history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraversalHistoryDiagnostics {
    pub sources: Vec<TraversalSourceHistoryDiagnostics>,
}

/// Serializable source-level history diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraversalSourceHistoryDiagnostics {
    pub source: String,
    pub success_count: u64,
    pub failure_count: u64,
    pub consecutive_failures: u32,
    pub success_rate_per_mille: Option<u16>,
    pub last_success_age_ms: Option<u64>,
    pub last_failure_age_ms: Option<u64>,
    pub cooldown_remaining_ms: Option<u64>,
}

pub fn traversal_history_path(config: &Config) -> Option<PathBuf> {
    let config_path = config.config_path.as_ref()?;
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    Some(dir.join(TRAVERSAL_HISTORY_FILE_NAME))
}

fn cooldown_until(now: u64, consecutive_failures: u32) -> Option<u64> {
    match consecutive_failures {
        0..=2 => None,
        3..=4 => Some(now.saturating_add(SHORT_COOLDOWN_MS)),
        _ => Some(now.saturating_add(LONG_COOLDOWN_MS)),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_success_failure_and_cooldown() {
        let mut history = TraversalHistory::default();
        history.record_failure(CandidatePairSource::Predicted);
        history.record_failure(CandidatePairSource::Predicted);
        assert!(!history.source_in_cooldown(CandidatePairSource::Predicted));

        history.record_failure(CandidatePairSource::Predicted);
        assert!(history.source_in_cooldown(CandidatePairSource::Predicted));

        history.record_success(CandidatePairSource::Predicted);
        let entry = history.source(CandidatePairSource::Predicted).unwrap();
        assert_eq!(entry.success_count, 1);
        assert_eq!(entry.failure_count, 3);
        assert_eq!(entry.consecutive_failures, 0);
        assert_eq!(entry.cooldown_until_ms, None);
        assert_eq!(entry.success_rate_per_mille(), Some(250));
    }

    #[test]
    fn saves_and_loads_history_file() {
        let path = std::env::temp_dir().join(format!(
            "p2wlan-traversal-history-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let mut history = TraversalHistory::default();
        history.record_success(CandidatePairSource::PeerReflexive);
        history.save(&path).unwrap();

        let loaded = TraversalHistory::load(Some(&path));
        assert_eq!(
            loaded
                .source(CandidatePairSource::PeerReflexive)
                .unwrap()
                .success_count,
            1
        );

        let _ = fs::remove_file(path);
    }
}
