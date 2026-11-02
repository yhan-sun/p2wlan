//! Per-run diagnostics credential in the Harmony application's private directory.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

pub(crate) struct DiagnosticsAuth {
    path: PathBuf,
    token: String,
}

impl DiagnosticsAuth {
    pub(crate) fn create(path: PathBuf) -> io::Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "diagnostics directory missing")
        })?;
        let mut bytes = [0_u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let temporary = parent.join(format!(
            ".diag-auth.{}.{}.tmp",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        // The identity/settings directory already exists and belongs to the app.
        // Publish atomically so a reader never observes a partially written token.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = file
            .write_all(token.as_bytes())
            .and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = result.and_then(|_| fs::rename(&temporary, &path)) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(Self { path, token })
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DiagnosticsAuth {
    fn drop(&mut self) {
        // Engine sessions are serialized by the lifecycle registry. A late
        // cleanup must still leave a replaced credential untouched.
        let mut current = Vec::with_capacity(65);
        if File::open(&self.path)
            .and_then(|file| file.take(65).read_to_end(&mut current))
            .is_ok()
            && current == self.token.as_bytes()
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "p2wlan-harmony-auth-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn publishes_private_random_token_and_removes_on_exit() {
        let dir = directory();
        let path = dir.join("p2wlan-daemon.diag-auth");
        let first = DiagnosticsAuth::create(path.clone()).unwrap();
        let token = first.token().to_owned();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(fs::read_to_string(first.path()).unwrap(), token);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(first);
        assert!(!path.exists());
        let next = DiagnosticsAuth::create(path.clone()).unwrap();
        assert_ne!(next.token(), token);
        drop(next);
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn failed_start_cleanup_preserves_a_successor_credential() {
        let dir = directory();
        let path = dir.join("p2wlan-daemon.diag-auth");
        let old = DiagnosticsAuth::create(path.clone()).unwrap();
        let successor = DiagnosticsAuth::create(path.clone()).unwrap();
        drop(old);
        assert_eq!(fs::read_to_string(&path).unwrap(), successor.token());
        drop(successor);
        assert!(!path.exists());
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn publication_error_leaves_no_temporary_credential() {
        let dir = directory();
        let path = dir.join("p2wlan-daemon.diag-auth");
        fs::create_dir(&path).unwrap();
        assert!(DiagnosticsAuth::create(path.clone()).is_err());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
