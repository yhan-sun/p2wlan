//! Embed the git commit and a per-build build id into the daemon binary so
//! `/status.version` (and `--build-info`) can prove WHICH commit is running.
//!
//! `P2WLAN_GIT_COMMIT` is the full SHA-1 of `HEAD` at compile time; fallback
//! is `unknown` when git is unavailable (e.g. a source tarball).  Development
//! builds also embed an explicit dirty marker and a hash of the checkout
//! status/diff, so they can never be mistaken for a clean release build. The
//! hash is refreshed whenever this build script is recompiled.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn git_head() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!commit.is_empty()).then_some(commit)
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
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
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
    if let Some(symbolic_ref) = git_output(&["symbolic-ref", "--quiet", "--short", "HEAD"]) {
        let symbolic_ref = symbolic_ref.trim();
        if !symbolic_ref.is_empty() {
            println!("cargo:rerun-if-changed=../../.git/refs/heads/{symbolic_ref}");
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

fn checkout_state() -> (bool, String) {
    let status = git_output(&["status", "--porcelain=v1", "--untracked-files=all"])
        .unwrap_or_else(|| "git-unavailable".to_string());
    if status.trim().is_empty() {
        return (false, String::new());
    }
    // `git hash-object` gives a deterministic content hash without adding a
    // build-script crypto dependency. Include status, the complete tracked
    // diff, and the bytes of every untracked file.
    let diff = git_output(&["diff", "HEAD", "--no-ext-diff", "--binary"]).unwrap_or_default();
    let untracked_paths =
        git_output(&["ls-files", "--others", "--exclude-standard", "-z"]).unwrap_or_default();
    let untracked: Vec<(String, Vec<u8>)> = untracked_paths
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(|path| {
            // Cargo does not know about an untracked file, so it will not
            // rerun this build script when that file's contents change unless
            // the path is explicitly registered here. Without this, two
            // dirty builds could report the same identity after an untracked
            // staging/template file was edited in place.
            println!("cargo:rerun-if-changed={path}");
            let bytes = std::fs::read(path)
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
    use super::dirty_material;

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
}

fn main() {
    let commit = git_head().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=P2WLAN_GIT_COMMIT={commit}");
    let (dirty, diff_hash) = checkout_state();
    println!("cargo:rustc-env=P2WLAN_DIRTY={dirty}");
    println!("cargo:rustc-env=P2WLAN_DIFF_HASH={diff_hash}");
    let build_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let build_id = if dirty {
        format!(
            "{}-dirty-{}-{build_ms}",
            commit.get(..12).unwrap_or(&commit),
            diff_hash.get(..12).unwrap_or(&diff_hash)
        )
    } else {
        format!("{}-{build_ms}", commit.get(..12).unwrap_or(&commit))
    };
    println!("cargo:rustc-env=P2WLAN_BUILD_ID={build_id}");
    println!("cargo:rustc-env=P2WLAN_BUILD_TIME_MS={build_ms}");
    // Re-run when the checked-out commit moves so stale builds never claim a
    // newer commit than they were compiled from. The concrete branch ref is
    // essential because `.git/HEAD` usually remains unchanged across commits.
    print_git_identity_watchers();
}
