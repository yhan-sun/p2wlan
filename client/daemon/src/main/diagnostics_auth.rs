use rand::RngCore;
use std::fs as auth_fs;
use std::path::{Path as AuthPath, PathBuf as AuthPathBuf};
use zeroize::Zeroizing;

/// Owns the per-process diagnostics session secret and its discovery file.
///
/// The guard is deliberately not `Debug`: the secret must never be rendered in
/// logs or panic diagnostics. The fixed discovery path is only published after
/// the instance lock has been acquired by the caller.
struct DiagnosticsAuthGuard {
    path: AuthPathBuf,
    _token: Zeroizing<String>,
}

impl DiagnosticsAuthGuard {
    fn prepare(
        config: &mut Config,
        config_path: &AuthPath,
    ) -> p2pnet_daemon::Result<Option<Self>> {
        if !config.diagnostics.enabled {
            return Ok(None);
        }

        let dir = config
            .diagnostics
            .log_path
            .as_ref()
            .and_then(|log| log.parent().map(AuthPath::to_path_buf))
            .or_else(|| config_path.parent().map(AuthPath::to_path_buf))
            .unwrap_or_else(|| AuthPathBuf::from("."));
        auth_fs::create_dir_all(&dir).map_err(|error| {
            DaemonError::Config(format!(
                "failed to create diagnostics auth directory {}: {error}",
                dir.display()
            ))
        })?;

        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = Zeroizing::new(hex::encode(bytes));
        let path = dir.join("p2wlan-daemon.diag-auth");
        let temp_path = dir.join(format!(
            ".p2wlan-daemon.diag-auth.{}.tmp",
            hex::encode(&bytes[..12])
        ));

        let result = (|| -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp_path)?;
            file.write_all(token.as_bytes())?;
            file.flush()?;
            restrict_auth_file(&temp_path)?;
            file.sync_all()?;
            drop(file);

            // Unix rename is an atomic replacement. Windows' std::fs::rename
            // cannot replace an existing file, so remove only the fixed stale
            // path after the new file has been fully written and ACL-checked.
            #[cfg(windows)]
            match auth_fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            auth_fs::rename(&temp_path, &path)?;
            if let Err(error) = restrict_auth_file(&path) {
                let _ = auth_fs::remove_file(&path);
                return Err(error);
            }
            #[cfg(unix)]
            std::fs::File::open(&dir)?.sync_all()?;
            Ok(())
        })();

        if let Err(error) = result {
            let _ = auth_fs::remove_file(&temp_path);
            return Err(DaemonError::Config(format!(
                "failed to publish diagnostics auth file {}: {error}",
                path.display()
            )));
        }

        config.diagnostics.auth_token = Some(token.to_string());
        config.diagnostics.auth_token_path = Some(path.clone());
        Ok(Some(Self {
            path,
            _token: token,
        }))
    }

}

impl Drop for DiagnosticsAuthGuard {
    fn drop(&mut self) {
        match auth_fs::remove_file(&self.path) {
            Ok(()) => info!("Removed diagnostics auth token file {}", self.path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!(
                "Failed to remove diagnostics auth token file {}: {error}",
                self.path.display()
            ),
        }
    }
}

#[cfg(unix)]
fn restrict_auth_file(path: &AuthPath) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = auth_fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    auth_fs::set_permissions(path, permissions)
}

#[cfg(windows)]
fn restrict_auth_file(path: &AuthPath) -> std::io::Result<()> {
    let username = std::env::var("USERNAME").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "USERNAME is unavailable; refusing an unprotected diagnostics auth file",
        )
    })?;
    let account = format!(r"{username}:F");
    let status = std::process::Command::new("icacls")
        .args([
            path.as_os_str(),
            std::ffi::OsStr::new("/inheritance:r"),
            std::ffi::OsStr::new("/grant:r"),
            account.as_ref(),
        ])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("icacls exited with {status}"),
        ))
    }
}
