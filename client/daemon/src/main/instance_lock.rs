use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use crate::error::{DaemonError, Result};

#[derive(Debug)]
pub struct DaemonInstanceLock {
    _file: File,
    pub path: PathBuf,
}

impl DaemonInstanceLock {
    pub fn acquire(config_path: &Path) -> Result<Self> {
        Self::lock(config_path, ".lock", true)
    }

    pub(super) fn acquire_for_edit(config_path: &Path) -> Result<Self> {
        Self::lock(config_path, ".lock", false)
    }

    #[cfg(not(unix))]
    pub(super) fn acquire_for_save(config_path: &Path) -> Result<Self> {
        Self::lock(config_path, ".write.lock", false)
    }

    fn lock(config_path: &Path, suffix: &str, record_pid: bool) -> Result<Self> {
        let config_path =
            std::fs::canonicalize(config_path).unwrap_or_else(|_| absolute_path(config_path));
        let mut lock_path = config_path.as_os_str().to_os_string();
        lock_path.push(suffix);
        let path = PathBuf::from(lock_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                DaemonError::Config(format!(
                    "failed to create daemon lock directory {}: {error}",
                    parent.display()
                ))
            })?;
        }

        let mut open = OpenOptions::new();
        open.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        // On Unix an existing root-owned read-only lock still admits flock.
        // Windows requires a writable handle for an exclusive byte-range lock.
        if record_pid || cfg!(windows) || !path.exists() {
            open.write(true).create(true);
        }
        let mut file = open.open(&path).map_err(|error| {
            DaemonError::Config(format!(
                "failed to open daemon lock file {}: {error}",
                path.display()
            ))
        })?;
        if !file.metadata()?.is_file() {
            return Err(DaemonError::Config(
                "daemon lock must be a regular file".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if file.metadata()?.nlink() != 1 {
                return Err(DaemonError::Config("daemon lock must have one link".into()));
            }
        }

        match file.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if suffix == ".write.lock" {
                    return Err(DaemonError::Config(
                        "another process is saving this config".into(),
                    ));
                }
                return Err(DaemonError::Config(format!(
                    "another P2WLAN daemon is already running for config {}",
                    config_path.display()
                )));
            }
            #[cfg(windows)]
            Err(error) => {
                // Windows maps LockFileEx contention and some sharing
                // violations to platform-specific errors instead of
                // WouldBlock. The safe interpretation is still "an owner is
                // present": fail closed before any session file is touched.
                if suffix == ".write.lock" {
                    return Err(DaemonError::Config(format!(
                        "could not lock config for saving: {error}"
                    )));
                }
                return Err(DaemonError::Config(format!(
                    "another P2WLAN daemon is already running for config {} ({error})",
                    config_path.display()
                )));
            }
            #[cfg(not(windows))]
            Err(error) => {
                return Err(DaemonError::Config(format!(
                    "failed to lock daemon instance file {}: {error}",
                    path.display()
                )));
            }
        }

        if !record_pid {
            return Ok(Self { _file: file, path });
        }
        file.set_len(0).map_err(|error| {
            DaemonError::Config(format!(
                "failed to reset daemon lock file {}: {error}",
                path.display()
            ))
        })?;
        writeln!(file, "{}", std::process::id()).map_err(|error| {
            DaemonError::Config(format!(
                "failed to write daemon PID to {}: {error}",
                path.display()
            ))
        })?;

        Ok(Self { _file: file, path })
    }
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|current| current.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}
