//! Embed the git commit and a per-build build id into the daemon binary so
//! `/status.version` (and `--build-info`) can prove WHICH commit is running.
//!
//! `P2WLAN_GIT_COMMIT` is the full SHA-1 of `HEAD` at compile time; fallback
//! is `unknown` when git is unavailable (e.g. a source tarball).  Development
//! builds also embed an explicit dirty marker and a hash of the checkout
//! status/diff, so they can never be mistaken for a clean release build. The
//! hash is refreshed whenever this build script is recompiled.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn git_root() -> Option<PathBuf> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let output = Command::new("git")
        .current_dir(manifest_dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!root.is_empty()).then_some(PathBuf::from(root))
}

fn git_head(repo_root: &Path) -> Option<String> {
    let commit = git_output(repo_root, &["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    (!commit.is_empty()).then_some(commit)
}

fn git_output(repo_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Print the concrete git ref that backs `HEAD` as a Cargo input.
///
/// Watching `.git/HEAD` alone is insufficient on a normal branch: a commit
/// updates `.git/refs/heads/<branch>` while `.git/HEAD` continues to contain
/// the same symbolic-ref text. Watching only the refs directory is also not
/// recursive, so Cargo can reuse a build script result and embed the previous
/// commit identity after a commit or checkout. The concrete ref closes that
/// identity gap while the HEAD/packed-refs watches retain detached-head and
/// packed-ref coverage.
fn print_git_identity_watchers() {
    let Some(repo_root) = git_root() else {
        return;
    };
    for path in [".git/HEAD", ".git/index", ".git/packed-refs"] {
        println!("cargo:rerun-if-changed={}", repo_root.join(path).display());
    }
    if let Some(symbolic_ref) =
        git_output(&repo_root, &["symbolic-ref", "--quiet", "--short", "HEAD"])
    {
        let symbolic_ref = symbolic_ref.trim();
        if !symbolic_ref.is_empty() {
            println!(
                "cargo:rerun-if-changed={}",
                repo_root
                    .join(".git/refs/heads")
                    .join(symbolic_ref)
                    .display()
            );
        }
    }
}

/// Build deterministic dirty material. Git status names an untracked file,
/// but does not include its contents; including the bytes here prevents two
/// different dirty source trees from sharing one build identity.
fn dirty_material(status: &str, tracked_diff: &str, untracked: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(status.as_bytes());
    material.extend_from_slice(tracked_diff.as_bytes());
    for (path, bytes) in untracked {
        material.extend_from_slice(b"\n-- untracked: ");
        material.extend_from_slice(path.as_bytes());
        material.extend_from_slice(b" --\n");
        material.extend_from_slice(bytes);
    }
    material
}

/// Cargo interprets `rerun-if-changed` relative to the package directory
/// (`client/daemon`), while `git ls-files` returns paths relative to the
/// repository root.  Always produce a path rooted at the checkout so an
/// untracked file outside the daemon crate also invalidates the build script.
fn repo_watch_path(repo_relative_path: &str, manifest_dir: &Path) -> PathBuf {
    manifest_dir.join(repo_relative_path)
}

/// Keep the embedded identity reproducible.  A wall-clock timestamp in a
/// rustc environment variable changes the executable on every rebuild even
/// when the checkout is byte-for-byte identical, which makes an A/B or
/// Mini/Air SHA gate unusable.  Callers that need a meaningful build time can
/// provide `P2WLAN_BUILD_EPOCH_MS`; otherwise the runtime timeline remains the
/// source of truth and `built_at_ms` is reported as zero.
fn build_epoch_ms() -> u128 {
    std::env::var("P2WLAN_BUILD_EPOCH_MS")
        .ok()
        .and_then(|value| value.parse::<u128>().ok())
        .unwrap_or_default()
}

const SOURCE_IDENTITY_ENV: [&str; 4] = [
    "P2WLAN_SOURCE_GIT_COMMIT",
    "P2WLAN_SOURCE_BUILD_ID",
    "P2WLAN_SOURCE_DIRTY",
    "P2WLAN_SOURCE_DIFF_HASH",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceIdentity {
    commit: String,
    build_id: String,
    dirty: bool,
    diff_hash: String,
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_source_identity(
    commit: &str,
    build_id: &str,
    dirty_value: &str,
    diff_hash: &str,
) -> Result<SourceIdentity, String> {
    if !is_hex(commit, 40) {
        return Err(format!(
            "P2WLAN_SOURCE_GIT_COMMIT must be a 40-character hexadecimal SHA-1, got {commit:?}"
        ));
    }
    let dirty = match dirty_value {
        "true" => true,
        "false" => false,
        _ => {
            return Err(format!(
                "P2WLAN_SOURCE_DIRTY must be exactly true or false, got {dirty_value:?}"
            ));
        }
    };
    if dirty {
        if !is_hex(diff_hash, 40) {
            return Err(format!(
                "dirty source identity requires a 40-character hexadecimal diff hash, got {diff_hash:?}"
            ));
        }
    } else if !diff_hash.is_empty() {
        return Err(format!(
            "clean source identity requires an empty diff hash, got {diff_hash:?}"
        ));
    }
    let expected_build_id = if dirty {
        format!("{}-dirty-{}", &commit[..12], &diff_hash[..12])
    } else {
        commit[..12].to_string()
    };
    if build_id != expected_build_id {
        return Err(format!(
            "P2WLAN_SOURCE_BUILD_ID does not match commit/dirty state: expected {expected_build_id:?}, got {build_id:?}"
        ));
    }
    Ok(SourceIdentity {
        commit: commit.to_string(),
        build_id: build_id.to_string(),
        dirty,
        diff_hash: diff_hash.to_string(),
    })
}

fn source_env(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} contains non-Unicode bytes")),
    }
}

fn frozen_source_identity() -> Result<Option<SourceIdentity>, String> {
    let values = [
        (SOURCE_IDENTITY_ENV[0], source_env(SOURCE_IDENTITY_ENV[0])?),
        (SOURCE_IDENTITY_ENV[1], source_env(SOURCE_IDENTITY_ENV[1])?),
        (SOURCE_IDENTITY_ENV[2], source_env(SOURCE_IDENTITY_ENV[2])?),
        (SOURCE_IDENTITY_ENV[3], source_env(SOURCE_IDENTITY_ENV[3])?),
    ];
    let provided = values.iter().filter(|(_, value)| value.is_some()).count();
    if provided == 0 {
        return Ok(None);
    }
    if provided != values.len() {
        let missing = values
            .iter()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "frozen source identity must provide all fields; missing: {missing}"
        ));
    }
    validate_source_identity(
        values[0].1.as_deref().expect("checked above"),
        values[1].1.as_deref().expect("checked above"),
        values[2].1.as_deref().expect("checked above"),
        values[3].1.as_deref().expect("checked above"),
    )
    .map(Some)
}

fn build_identity(commit: &str, dirty: bool, diff_hash: &str) -> String {
    if dirty {
        format!(
            "{}-dirty-{}",
            commit.get(..12).unwrap_or(commit),
            diff_hash.get(..12).unwrap_or(diff_hash)
        )
    } else {
        commit.get(..12).unwrap_or(commit).to_string()
    }
}

fn checkout_state() -> (bool, String) {
    let Some(repo_root) = git_root() else {
        return (true, "git-unavailable".to_string());
    };
    let status = git_output(
        &repo_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )
    .unwrap_or_else(|| "git-unavailable".to_string());
    if status.trim().is_empty() {
        return (false, String::new());
    }
    // `git hash-object` gives a deterministic content hash without adding a
    // build-script crypto dependency. Include status, the complete tracked
    // diff, and the bytes of every untracked file.
    let diff =
        git_output(&repo_root, &["diff", "HEAD", "--no-ext-diff", "--binary"]).unwrap_or_default();
    let untracked_paths = git_output(
        &repo_root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )
    .unwrap_or_default();
    let untracked: Vec<(String, Vec<u8>)> = untracked_paths
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(|path| {
            // Cargo does not know about an untracked file, so it will not
            // rerun this build script when that file's contents change unless
            // the path is explicitly registered here. Without this, two
            // dirty builds could report the same identity after an untracked
            // staging/template file was edited in place.
            println!(
                "cargo:rerun-if-changed={}",
                repo_watch_path(path, &repo_root).display()
            );
            let bytes = std::fs::read(repo_watch_path(path, &repo_root))
                .unwrap_or_else(|err| format!("unreadable untracked file: {err}").into_bytes());
            (path.to_string(), bytes)
        })
        .collect();
    let material = dirty_material(&status, &diff, &untracked);
    let hash = Command::new("git")
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(&material)?;
            }
            child.wait_with_output()
        });
    let hash = match hash {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => "dirty".to_string(),
    };
    (
        true,
        if hash.is_empty() {
            "dirty".to_string()
        } else {
            hash
        },
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{build_identity, dirty_material, repo_watch_path, validate_source_identity};

    #[test]
    fn untracked_content_changes_dirty_material() {
        let first = dirty_material(
            "?? staging.env.example\n",
            "",
            &[("staging.env.example".into(), b"CONTROL=a\n".to_vec())],
        );
        let second = dirty_material(
            "?? staging.env.example\n",
            "",
            &[("staging.env.example".into(), b"CONTROL=b\n".to_vec())],
        );
        assert_ne!(first, second);
    }

    #[test]
    fn tracked_diff_and_path_are_part_of_dirty_material() {
        let first = dirty_material(" M file.rs\n", "old", &[]);
        let second = dirty_material(" M file.rs\n", "new", &[]);
        let third = dirty_material("?? other.rs\n", "old", &[]);
        assert_ne!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn untracked_watch_path_is_relative_to_the_repository_root() {
        let watch = repo_watch_path("scripts/staging/example.env", Path::new("/checkout"));
        assert_eq!(watch, Path::new("/checkout/scripts/staging/example.env"));
    }

    #[test]
    fn build_identity_is_stable_and_marks_dirty_diff() {
        assert_eq!(
            build_identity("0123456789abcdef", false, "ignored"),
            "0123456789ab"
        );
        assert_eq!(
            build_identity("0123456789abcdef", true, "fedcba9876543210"),
            "0123456789ab-dirty-fedcba987654"
        );
    }

    #[test]
    fn frozen_source_identity_accepts_clean_and_dirty_contracts() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            validate_source_identity(commit, "0123456789ab", "false", "").unwrap(),
            super::SourceIdentity {
                commit: commit.to_string(),
                build_id: "0123456789ab".to_string(),
                dirty: false,
                diff_hash: String::new(),
            }
        );
        assert!(validate_source_identity(
            commit,
            "0123456789ab-dirty-fedcba987654",
            "true",
            "fedcba98765432100123456789abcdef01234567"
        )
        .is_ok());
    }

    #[test]
    fn frozen_source_identity_rejects_malformed_contracts() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let invalid = [
            ("not-a-commit", "0123456789ab", "false", ""),
            (commit, "0123456789ab", "maybe", ""),
            (
                commit,
                "0123456789ab",
                "false",
                "fedcba98765432100123456789abcdef01234567",
            ),
            (commit, "0123456789ab-dirty-fedcba987654", "true", ""),
            (commit, "wrong-build-id", "false", ""),
        ];
        for (commit, build_id, dirty, diff_hash) in invalid {
            assert!(
                validate_source_identity(commit, build_id, dirty, diff_hash).is_err(),
                "invalid frozen identity unexpectedly accepted: {} {} {} {}",
                commit,
                build_id,
                dirty,
                diff_hash,
            );
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=P2WLAN_BUILD_EPOCH_MS");
    for name in SOURCE_IDENTITY_ENV {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let frozen = frozen_source_identity()
        .unwrap_or_else(|error| panic!("invalid frozen source identity override: {}", error));
    let (commit, dirty, diff_hash, build_id) = if let Some(identity) = frozen {
        (
            identity.commit,
            identity.dirty,
            identity.diff_hash,
            identity.build_id,
        )
    } else {
        let commit = git_root()
            .as_deref()
            .and_then(git_head)
            .unwrap_or_else(|| "unknown".to_string());
        let (dirty, diff_hash) = checkout_state();
        let build_id = build_identity(&commit, dirty, &diff_hash);
        (commit, dirty, diff_hash, build_id)
    };
    println!("cargo:rustc-env=P2WLAN_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=P2WLAN_DIRTY={dirty}");
    println!("cargo:rustc-env=P2WLAN_DIFF_HASH={diff_hash}");
    let build_ms = build_epoch_ms();
    println!("cargo:rustc-env=P2WLAN_BUILD_ID={build_id}");
    println!("cargo:rustc-env=P2WLAN_BUILD_TIME_MS={build_ms}");
    // Re-run when the checked-out commit moves so stale builds never claim a
    // newer commit than they were compiled from. The concrete branch ref is
    // essential because `.git/HEAD` usually remains unchanged across commits.
    print_git_identity_watchers();
}
