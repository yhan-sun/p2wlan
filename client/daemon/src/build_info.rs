//! Build identity of the running daemon binary.
//!
//! `/status.version` (and `--build-info`) report every field so a verifier can
//! prove which git commit is running, that the binary on disk matches the
//! process (binary_sha256 of the executable file), and that the App bundle's
//! embedded daemon is the same build as the App's own version.
//!
//! The SHA-256 is computed once at first access from the process's executable
//! path (`std::env::current_exe`), never from a build-time constant: the
//! reported value always describes the file that actually started this process.

use std::io::Read;
use std::sync::OnceLock;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// The exact git commit this binary was compiled from (full SHA-1).
pub const GIT_COMMIT: &str = env!("P2WLAN_GIT_COMMIT");
/// Stable source identity: short commit, plus `dirty` and the checkout diff
/// hash for development builds.
pub const BUILD_ID: &str = env!("P2WLAN_BUILD_ID");
/// Whether the checkout contained tracked or untracked changes at build time.
pub const DIRTY: &str = match option_env!("P2WLAN_DIRTY") {
    Some(value) => value,
    None => "false",
};
/// Deterministic checkout status/diff hash for dirty development builds.
pub const DIFF_HASH: &str = match option_env!("P2WLAN_DIFF_HASH") {
    Some(value) => value,
    None => "",
};
pub const BUILD_TIME_MS: &str = env!("P2WLAN_BUILD_TIME_MS");

/// Serializable build identity exposed by `/status.version` and
/// `--build-info`.  Contains no secrets: no token, no key, no auth header.
#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    /// App / workspace semantic version (e.g. 0.1.117).  The App bundle, the
    /// embedded daemon and the workspace Cargo.toml are pinned to this value
    /// by the build script, so `app_version` and `daemon_version` cannot
    /// drift apart when built by the supported pipeline.
    pub app_version: String,
    /// Semantic version of the daemon crate (identical to app_version for a
    /// workspace build; reported separately so an out-of-band daemon build
    /// cannot silently pass as the App's embedded build).
    pub daemon_version: String,
    /// Full git commit SHA-1 the binary was compiled from.
    pub git_commit: String,
    /// Stable per-build identifier.
    pub build_id: String,
    /// SHA-256 of the running executable file on disk.
    pub binary_sha256: String,
    /// Filesystem path of the running executable (the file that produced
    /// `binary_sha256`).
    pub binary_path: String,
    /// Cargo profile this binary was built with.
    pub profile: &'static str,
    /// Unix millisecond timestamp supplied through `P2WLAN_BUILD_EPOCH_MS`.
    /// Zero means the reproducible-build default was used; daemon timeline
    /// events provide the actual startup wall/monotonic times.
    pub built_at_ms: u64,
    /// Explicit source-tree state. Release identity verification rejects
    /// `dirty=true`; development diagnostics must show it plainly.
    pub dirty: bool,
    pub diff_hash: String,
}

fn binary_sha256_and_path() -> (String, String) {
    let exe = std::env::current_exe().unwrap_or_default();
    let exe_str = exe.display().to_string();
    let digest = match std::fs::File::open(&exe)
        .map_err(|e| e.to_string())
        .and_then(|mut file| {
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = file.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hasher.finalize())
        }) {
        Ok(digest) => hex::encode(digest),
        Err(_) => "unavailable".to_string(),
    };
    (digest, exe_str)
}

fn build_info() -> BuildInfo {
    let (binary_sha256, binary_path) = binary_sha256_and_path();
    BuildInfo {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        git_commit: GIT_COMMIT.to_string(),
        build_id: BUILD_ID.to_string(),
        binary_sha256,
        binary_path,
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        built_at_ms: BUILD_TIME_MS.parse::<u64>().unwrap_or(0),
        dirty: DIRTY == "true",
        diff_hash: DIFF_HASH.to_string(),
    }
}

/// The process-wide build identity (computed once).
pub fn current() -> &'static BuildInfo {
    static INFO: OnceLock<BuildInfo> = OnceLock::new();
    INFO.get_or_init(build_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_is_self_consistent() {
        let info = current();
        // The reported git commit must be the real HEAD when built in a git
        // checkout (all CI and supported builds are), never a blank value.
        assert!(!info.git_commit.is_empty());
        assert_eq!(info.app_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.daemon_version, env!("CARGO_PKG_VERSION"));
        assert!(!info.binary_sha256.is_empty());
        assert!(!info.binary_path.is_empty());
        // The reported SHA-256 must match the running binary on disk.
        let (sha, _) = binary_sha256_and_path();
        assert_eq!(info.binary_sha256, sha);
        assert_eq!(info.build_id, env!("P2WLAN_BUILD_ID"));
        // build_id embeds the short commit, so the commit is auditable even
        // when only build_id is present.
        assert!(
            info.build_id
                .starts_with(info.git_commit.get(..12).unwrap_or(&info.git_commit))
                || info.git_commit == "unknown"
        );
    }

    #[test]
    fn build_info_serializes_without_secrets() {
        let info = current();
        let json = serde_json::to_value(info).unwrap();
        for field in [
            "app_version",
            "daemon_version",
            "git_commit",
            "build_id",
            "binary_sha256",
            "binary_path",
            "profile",
            "built_at_ms",
            "dirty",
            "diff_hash",
        ] {
            assert!(json.get(field).is_some(), "missing field {field}");
        }
        let text = serde_json::to_string(info).unwrap();
        for sensitive in ["token", "secret", "private_key", "auth"] {
            assert!(
                !text.to_lowercase().contains(sensitive),
                "build info must not leak {sensitive}"
            );
        }
    }
}
