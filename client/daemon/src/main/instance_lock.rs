use fs2::FileExt;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::path::Path;

#[derive(Debug)]
struct DaemonInstanceLock {
    _file: File,
    path: PathBuf,
}

impl DaemonInstanceLock {
    fn acquire(config_path: &Path) -> p2pnet_daemon::Result<Self> {
        let config_path = std::fs::canonicalize(config_path)
            .unwrap_or_else(|_| absolute_path(config_path));
        let path = daemon_lock_path(&config_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                DaemonError::Config(format!(
                    "failed to create daemon lock directory {}: {error}",
                    parent.display()
                ))
            })?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| {
                DaemonError::Config(format!(
                    "failed to open daemon lock file {}: {error}",
                    path.display()
                ))
            })?;

        match file.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
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

fn daemon_lock_path(config_path: &Path) -> PathBuf {
    let mut path = config_path.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}
