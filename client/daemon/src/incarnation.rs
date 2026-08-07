//! Persistent monotonic daemon incarnation counter.
//!
//! Fresh-mapping prediction labels embed the sender's incarnation
//! (`predicted_fresh:<incarnation>:<generation>`) and candidate generations
//! embed it in their high bits, so cross-process ordering never depends on the
//! wall clock: the persisted counter is strictly incremented per boot, which
//! stays monotonic across clock rollbacks and restarts that land in the same
//! millisecond.  The wall clock only seeds the very first boot.
//!
//! Monotonicity contract: the daemon only ever *claims* monotonicity when the
//! persisted state is trustworthy.  A missing file is a legitimate first boot
//! (seeded from the wall clock and persisted); a corrupt, unreadable or
//! version-incompatible file, an unwritable state directory, a missing config
//! path, or an incarnation counter at its limit all disable fresh prediction
//! for the boot instead of silently re-seeding from the wall clock — a
//! re-seed after a clock rollback would otherwise let an older incarnation
//! look newer than the high-water a receiver already recorded.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::Config;

pub const INCARNATION_FILE_NAME: &str = "incarnation.json";
const INCARNATION_VERSION: u8 = 1;
/// Fixed temporary-file name for the atomic rename.  The cross-process file
/// lock serializes writers, so a fixed name can never race two daemons, and a
/// crash between write and rename leaves only a stale temporary that the next
/// successful save overwrites.
const INCARNATION_TMP_FILE_NAME: &str = "incarnation.json.tmp";
/// Cross-process lock serializing the read -> increment -> write transaction,
/// so two daemons booted concurrently can never both reserve the same
/// incarnation.
const INCARNATION_LOCK_FILE_NAME: &str = "incarnation.lock";

/// Persisted incarnation state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncarnationState {
    pub version: u8,
    /// Strictly increasing per daemon boot; seeded from the wall clock on the
    /// very first boot.
    pub incarnation: u64,
    /// Wall-clock instant of the boot that reserved this incarnation, for
    /// diagnostics only.  Never used for ordering.
    pub last_boot_epoch_ms: u64,
}

/// Process-local copy of the current boot's incarnation, used by the signal
/// path (`next_candidate_generation`) without re-reading the state file.
static LOCAL_INCARNATION: AtomicU64 = AtomicU64::new(0);

/// Record the incarnation of the current boot for this process.
pub fn set_local_incarnation(incarnation: u64) {
    LOCAL_INCARNATION.store(incarnation, Ordering::Relaxed);
}

/// The current boot's incarnation, or 0 when no daemon was constructed yet.
pub fn local_incarnation() -> u64 {
    LOCAL_INCARNATION.load(Ordering::Relaxed)
}

pub fn incarnation_path(config: &Config) -> Option<PathBuf> {
    let config_path = config.config_path.as_ref()?;
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    Some(dir.join(INCARNATION_FILE_NAME))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// Pure monotonicity rule: the next incarnation is strictly greater than the
/// loaded one.
///
/// The wall clock ONLY seeds the very first boot (`loaded == None`); every
/// later boot strictly increments the persisted counter.  The counter never
/// follows a forward wall-clock jump: `now` is diagnostics-only for
/// subsequent boots, so an operator who sets the clock far into the future
/// cannot make the incarnation jump (and thereby burn the 41-bit encoding
/// headroom); a rollback stays harmless because the persisted counter is
/// never below its previous value.
fn next_incarnation(loaded: Option<u64>, now: u64) -> Option<u64> {
    match loaded {
        Some(loaded) => loaded.checked_add(1),
        None => now.checked_add(1),
    }
}

/// Load the persisted incarnation state.
///
/// Returns `Ok(None)` when the file does not exist (legitimate first boot).
/// Returns `Err(())` for every untrustworthy state: unreadable file, invalid
/// JSON, unknown version, or a zero incarnation.  An `Err` boot must disable
/// fresh prediction instead of re-seeding from the wall clock, because a
/// re-seed can regress below the incarnation receivers already recorded.
fn load(path: Option<&Path>) -> Result<Option<IncarnationState>, ()> {
    let Some(path) = path else {
        return Err(());
    };
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let state = serde_json::from_str::<IncarnationState>(&content).map_err(|_| ())?;
    if state.version != INCARNATION_VERSION || state.incarnation == 0 {
        return Err(());
    }
    Ok(Some(state))
}

/// Persist the state atomically: write the fixed temporary file, fsync it,
/// rename over the live file, then fsync the parent directory so the rename
/// itself survives a crash.  Must run while holding the incarnation lock.
///
/// The directory fsync is platform-specific: POSIX opens the directory and
/// calls `sync_all`, while Windows (which cannot open a directory for
/// synchronous I/O) uses the platform helper that no-ops there — an atomic
/// rename on NTFS is journaled, so the rename itself is durable once the file
/// is fsynced.
fn save(state: &IncarnationState, path: &Path) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp_path = parent.join(INCARNATION_TMP_FILE_NAME);
    let content = serde_json::to_vec_pretty(state)?;
    {
        let mut tmp = fs::File::create(&tmp_path)?;
        tmp.write_all(&content)?;
        tmp.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    sync_parent_directory(parent)
}

/// Fsync a directory so a completed rename survives a crash.
#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> std::io::Result<()> {
    fs::File::open(parent)?.sync_all()
}

/// Windows cannot open directories for synchronous I/O; the NTFS journal
/// makes the rename durable once the file itself was fsynced.
#[cfg(windows)]
fn sync_parent_directory(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Windows keeps no directory-fsync step: the platform helper is a no-op
/// (see [`sync_parent_directory`]).
#[cfg(not(any(unix, windows)))]
fn sync_parent_directory(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Reserve the next boot incarnation under the cross-process file lock,
/// persist it atomically, and record it as the process-local incarnation.
///
/// Returns `None` when no trustworthy monotonic incarnation exists for this
/// boot: every `None` caller must disable the fresh-prediction signal path
/// (the wall clock is never used as a fallback for an untrustworthy state).
///
/// - `config.config_path` is `None`: no stable state directory exists, so no
///   incarnation can be persisted across boots.
/// - The state file is missing: legitimate first boot, seeded from the wall
///   clock and persisted.
/// - The state file is corrupt / unreadable / version-incompatible: fresh
///   prediction is disabled for this boot; the file is left untouched.
/// - The state directory is unwritable: fresh prediction is disabled.
/// - The counter reached `u64::MAX`: fresh prediction is disabled instead of
///   wrapping back to a value receivers already saw.
pub fn next_boot_incarnation(config: &Config) -> Option<u64> {
    let now = now_ms();
    let path = match incarnation_path(config) {
        Some(path) => path,
        None => {
            warn!(
                "Fresh-mapping prediction disabled: no config path, so no durable incarnation state exists for this boot"
            );
            return None;
        }
    };
    let lock_path = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(INCARNATION_LOCK_FILE_NAME);

    // How many times a boot that finds the incarnation file missing with a
    // pre-existing lock file retries before treating the state as lost.
    // Another boot may have just created the lock and still be seeding under
    // the flock (its save lands after ours is released); the retry observes
    // that save.  A still-missing file after the retries is a state LOSS or a
    // crashed first boot: fresh prediction is disabled instead of re-seeding
    // from a wall clock that may have rolled back below the incarnations
    // receivers already recorded.
    const STATE_LOSS_CONFIRM_RETRIES: u32 = 3;
    let mut state_loss_confirms = STATE_LOSS_CONFIRM_RETRIES;

    let incarnation = loop {
        // A pre-existing lock file is evidence that some boot created it
        // before this one.  Combined with a missing incarnation file under
        // the flock it means the durable state is missing: either a
        // concurrent boot is still seeding (retried below) or the state was
        // LOST (refused).  The check itself races other boots' `open`, which
        // is exactly why the missing-file case below releases the flock and
        // retries instead of refusing on the first observation.
        let lock_existed_before = fs::metadata(&lock_path).is_ok();

        // Serialize the whole read -> increment -> write transaction across
        // processes.  `fs2` flock is advisory but every daemon uses it, so two
        // concurrently booted daemons can never both read the same old value.
        let lock_file = match fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) => {
                warn!(
                    "Fresh-mapping prediction disabled: cannot open the incarnation lock at {}: {error}",
                    lock_path.display()
                );
                return None;
            }
        };
        if let Err(error) = lock_file.lock_exclusive() {
            warn!(
                "Fresh-mapping prediction disabled: cannot lock the incarnation state at {}: {error}",
                lock_path.display()
            );
            return None;
        }
        let lock_guard = LockGuard(lock_file);

        let loaded = match load(Some(&path)) {
            Ok(loaded) => loaded,
            Err(()) => {
                warn!(
                    "Fresh-mapping prediction disabled for this boot: the persisted incarnation at {} is missing its trusted monotonic state (corrupt, unreadable, or an incompatible version); refusing to re-seed from the wall clock. Remove the file to re-seed deliberately.",
                    path.display()
                );
                return None;
            }
        };
        let loaded = match loaded {
            Some(loaded) => loaded,
            None if lock_existed_before => {
                // The lock predates this boot but the state file is still
                // missing: a concurrent first boot may be seeding under the
                // flock.  Release the flock and retry so its save is
                // observed; after the retry budget the state is lost.
                drop(lock_guard);
                if state_loss_confirms == 0 {
                    warn!(
                        "Fresh-mapping prediction disabled for this boot: the incarnation state at {} is missing but the lock file {} predates this boot, so this is a STATE LOSS (or a crashed first boot), not a first boot; refusing to re-seed from the wall clock below the incarnations receivers already recorded. Remove both files to re-seed deliberately.",
                        path.display(),
                        lock_path.display()
                    );
                    return None;
                }
                state_loss_confirms -= 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            None => {
                // Legitimate first boot: seed from the wall clock and persist
                // it so every later boot strictly increments.  If the seed
                // cannot be persisted there is no durable state at all, so
                // fresh prediction is disabled instead of claiming a
                // monotonicity we cannot uphold.
                let seed = IncarnationState {
                    version: INCARNATION_VERSION,
                    incarnation: now.max(1),
                    last_boot_epoch_ms: now,
                };
                if let Err(error) = save(&seed, &path) {
                    warn!(
                        "Fresh-mapping prediction disabled: failed to persist the first-boot incarnation at {}: {error}",
                        path.display()
                    );
                    return None;
                }
                set_local_incarnation(seed.incarnation);
                return Some(seed.incarnation);
            }
        };
        let Some(next) = next_incarnation(Some(loaded.incarnation), now) else {
            warn!(
                "Fresh-mapping prediction disabled: the persisted incarnation {} reached the u64 limit; refusing to wrap back to a value receivers already recorded",
                loaded.incarnation
            );
            return None;
        };
        let state = IncarnationState {
            version: INCARNATION_VERSION,
            incarnation: next,
            last_boot_epoch_ms: now,
        };
        if let Err(error) = save(&state, &path) {
            warn!(
                "Fresh-mapping prediction disabled: failed to persist the incremented incarnation at {}: {error}",
                path.display()
            );
            return None;
        }
        break next;
    };

    set_local_incarnation(incarnation);
    Some(incarnation)
}

/// RAII wrapper keeping the flock held for the transaction's duration.
struct LockGuard(std::fs::File);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(path: Option<PathBuf>) -> Config {
        let mut config = Config::generate_default("http://127.0.0.1:1", "test-network").unwrap();
        config.config_path = path;
        config
    }

    /// Isolate every test in its own directory so parallel tests never share
    /// the lock file or the incarnation file.
    fn isolate(name: &str) -> PathBuf {
        let unique = LOCAL_INCARNATION.load(Ordering::Relaxed)
            ^ (std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64);
        let dir = std::env::temp_dir().join(format!(
            "p2wlan-incarnation-test-{}-{name}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn first_boot_seeds_from_wall_clock() {
        assert_eq!(
            next_incarnation(None, 1_742_987_654_321),
            Some(1_742_987_654_322)
        );
        assert_eq!(next_incarnation(None, 0), Some(1));
        assert_eq!(next_incarnation(Some(u64::MAX), 1), None);
    }

    #[test]
    fn clock_rollback_never_reuses_an_incarnation() {
        let first = next_incarnation(Some(1_742_987_654_321), 1_742_987_654_321).unwrap();
        let second = next_incarnation(Some(first), 1_742_987_054_321).unwrap();
        assert!(second > first);
        let third = next_incarnation(Some(second), 1_742_000_000_000).unwrap();
        assert!(third > second);
    }

    #[test]
    fn same_millisecond_restart_still_advances() {
        let first = next_incarnation(Some(1_742_987_654_321), 1_742_987_654_321).unwrap();
        let second = next_incarnation(Some(first), 1_742_987_654_321).unwrap();
        assert!(second > first);
    }

    #[test]
    fn forward_clock_keeps_monotonicity() {
        let first = next_incarnation(Some(1_742_987_654_321), 1_742_987_654_321).unwrap();
        let second = next_incarnation(Some(first), 1_742_987_954_321).unwrap();
        assert!(second > first);
    }

    #[test]
    fn missing_file_is_a_first_boot_that_persists() {
        let dir = isolate("first-boot");
        let config = temp_config(Some(dir.join("config.json")));
        let first = next_boot_incarnation(&config).expect("first boot seeds");
        assert!(first >= 1);
        let second = next_boot_incarnation(&config).expect("second boot increments");
        assert!(second > first);
        // The file really exists now.
        let state = load(Some(&dir.join(INCARNATION_FILE_NAME)))
            .unwrap()
            .unwrap();
        assert_eq!(state.incarnation, second);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_config_path_disables_fresh_prediction() {
        let config = temp_config(None);
        assert_eq!(next_boot_incarnation(&config), None);
    }

    #[test]
    fn corrupt_file_disables_instead_of_reseeding() {
        let dir = isolate("corrupt");
        let path = dir.join(INCARNATION_FILE_NAME);
        fs::write(&path, "{not json").unwrap();
        let config = temp_config(Some(dir.join("config.json")));
        assert_eq!(next_boot_incarnation(&config), None);
        // The corrupt file is left untouched: the next boot still refuses
        // instead of re-seeding from a rolled-back clock.
        assert_eq!(fs::read_to_string(&path).unwrap(), "{not json");
        assert_eq!(next_boot_incarnation(&config), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_mismatch_disables_instead_of_reseeding() {
        let dir = isolate("version");
        let path = dir.join(INCARNATION_FILE_NAME);
        fs::write(
            &path,
            serde_json::to_string(&IncarnationState {
                version: 99,
                incarnation: 1_742_987_654_321,
                last_boot_epoch_ms: 0,
            })
            .unwrap(),
        )
        .unwrap();
        let config = temp_config(Some(dir.join("config.json")));
        assert_eq!(next_boot_incarnation(&config), None);
        assert_eq!(next_boot_incarnation(&config), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unavailable_state_parent_disables_instead_of_reseeding() {
        let dir = isolate("unavailable-parent");
        // Windows' read-only directory attribute does not prevent the owner
        // from creating files. A regular file as the config parent makes the
        // lock path unavailable on every supported platform.
        let config_parent = dir.join("not-a-directory");
        fs::write(&config_parent, b"not a directory").unwrap();
        let config = temp_config(Some(config_parent.join("config.json")));
        assert_eq!(next_boot_incarnation(&config), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_concurrent_boots_never_share_an_incarnation() {
        let dir = isolate("concurrent");
        let config = temp_config(Some(dir.join("config.json")));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let path = config.config_path.clone().unwrap();
            handles.push(std::thread::spawn(move || {
                let config = temp_config(Some(path));
                next_boot_incarnation(&config)
            }));
        }
        let mut values = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap()
                    .expect("boot reserves an incarnation")
            })
            .collect::<Vec<_>>();
        assert!(
            values.len() == 4,
            "every concurrent boot got an incarnation"
        );
        values.sort_unstable();
        values.dedup();
        assert_eq!(
            values.len(),
            4,
            "concurrent boots must reserve distinct incarnations"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_between_write_and_rename_keeps_the_old_state() {
        let dir = isolate("crash");
        let path = dir.join(INCARNATION_FILE_NAME);
        let first = IncarnationState {
            version: INCARNATION_VERSION,
            incarnation: 41,
            last_boot_epoch_ms: 40,
        };
        save(&first, &path).unwrap();
        // Simulate a crash after the temporary file was written but before
        // the rename: the live file keeps the old state and the next boot
        // increments from it, ignoring the stale temporary.
        let tmp = dir.join(INCARNATION_TMP_FILE_NAME);
        fs::write(
            &tmp,
            b"{\"version\":1,\"incarnation\":999,\"last_boot_epoch_ms\":999}",
        )
        .unwrap();
        let loaded = load(Some(&path)).unwrap().unwrap();
        assert_eq!(loaded.incarnation, 41);
        let next = next_incarnation(Some(loaded.incarnation), 41).unwrap();
        assert_eq!(next, 42);
        let state = IncarnationState {
            version: INCARNATION_VERSION,
            incarnation: next,
            last_boot_epoch_ms: 41,
        };
        save(&state, &path).unwrap();
        let after = load(Some(&path)).unwrap().unwrap();
        assert_eq!(after.incarnation, 42);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_round_trips_through_the_file() {
        let dir = isolate("roundtrip");
        let path = dir.join(INCARNATION_FILE_NAME);
        let state = IncarnationState {
            version: INCARNATION_VERSION,
            incarnation: 42,
            last_boot_epoch_ms: 41,
        };
        save(&state, &path).unwrap();
        let loaded = load(Some(&path)).unwrap().unwrap();
        assert_eq!(loaded, state);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn incarnation_at_u64_max_refuses_to_wrap() {
        let dir = isolate("max");
        let path = dir.join(INCARNATION_FILE_NAME);
        let state = IncarnationState {
            version: INCARNATION_VERSION,
            incarnation: u64::MAX,
            last_boot_epoch_ms: 41,
        };
        save(&state, &path).unwrap();
        let config = temp_config(Some(dir.join("config.json")));
        assert_eq!(next_boot_incarnation(&config), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_but_later_persisted_state_stays_monotonic() {
        let dir = isolate("later");
        let config = temp_config(Some(dir.join("config.json")));
        let first = next_boot_incarnation(&config).unwrap();
        // The operator deliberately deletes the durable state: the next boot
        // re-seeds, but only from a clock that is at least as new as the
        // persisted record.  A deliberate re-seed removes BOTH files; a
        // missing incarnation file with a pre-existing lock file is treated
        // as state loss (see `missing_file_with_existing_lock_is_state_loss`).
        fs::remove_file(dir.join(INCARNATION_FILE_NAME)).unwrap();
        fs::remove_file(dir.join(INCARNATION_LOCK_FILE_NAME)).unwrap();
        // A first boot is seeded from the wall clock. On a fast CI host both
        // calls can otherwise land in the same millisecond, which cannot
        // demonstrate the intended "later persisted state" property.
        let wait_started = std::time::Instant::now();
        while now_ms() <= first {
            assert!(
                wait_started.elapsed() < std::time::Duration::from_secs(1),
                "wall clock did not advance beyond the original incarnation"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let reseeded = next_boot_incarnation(&config).unwrap();
        assert!(reseeded > first);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_with_existing_lock_is_state_loss_not_first_boot() {
        let dir = isolate("lost-state");
        let config = temp_config(Some(dir.join("config.json")));
        let first = next_boot_incarnation(&config).unwrap();
        // The state file is deleted but the lock file survives (as after a
        // crash or a partial manual cleanup): the next boot must refuse to
        // re-seed from the wall clock, because a re-seed can regress below
        // the incarnation receivers already recorded.
        fs::remove_file(dir.join(INCARNATION_FILE_NAME)).unwrap();
        assert!(dir.join(INCARNATION_LOCK_FILE_NAME).exists());
        assert_eq!(next_boot_incarnation(&config), None);
        assert_eq!(next_boot_incarnation(&config), None);
        // The operator removes the lock file deliberately: re-seeding is
        // allowed again and stays above the first incarnation.
        fs::remove_file(dir.join(INCARNATION_LOCK_FILE_NAME)).unwrap();
        let reseeded = next_boot_incarnation(&config).unwrap();
        assert!(reseeded > first);
        let _ = fs::remove_dir_all(&dir);
    }
}
