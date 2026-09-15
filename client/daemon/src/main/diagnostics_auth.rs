use rand::RngCore;
use std::fs as auth_fs;
use std::path::{Path as AuthPath, PathBuf as AuthPathBuf};
use std::sync::{Arc as DiagnosticsArc, Mutex};
use std::time::Duration as AuthRepairDuration;
use zeroize::Zeroizing;

/// Owns the per-process diagnostics session secret and its discovery file.
///
/// The guard is deliberately not `Debug`: the secret must never be rendered in
/// logs or panic diagnostics. The fixed discovery path is only published after
/// the instance lock has been acquired by the caller.
struct DiagnosticsAuthGuard {
    path: AuthPathBuf,
    _token: Zeroizing<String>,
    repair_abort: Option<tokio::task::AbortHandle>,
    repair_lock: DiagnosticsArc<Mutex<()>>,
}

impl DiagnosticsAuthGuard {
    fn prepare(
        config: &mut Config,
        config_path: &AuthPath,
        diagnostics_client_sid: Option<&str>,
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
        let result = publish_auth_file(&path, token.as_str(), diagnostics_client_sid);

        if let Err(error) = result {
            return Err(DaemonError::Config(format!(
                "failed to publish diagnostics auth file {}: {error}",
                path.display()
            )));
        }

        config.diagnostics.auth_token = Some(token.to_string());
        config.diagnostics.auth_token_path = Some(path.clone());
        let repair_lock = DiagnosticsArc::new(Mutex::new(()));
        let repair_abort = spawn_auth_file_repair(
            path.clone(),
            token.clone(),
            diagnostics_client_sid.map(ToOwned::to_owned),
            repair_lock.clone(),
        );
        Ok(Some(Self {
            path,
            _token: token,
            repair_abort,
            repair_lock,
        }))
    }
}

impl Drop for DiagnosticsAuthGuard {
    fn drop(&mut self) {
        if let Some(abort) = self.repair_abort.take() {
            abort.abort();
        }
        // The repair loop performs synchronous filesystem operations while it
        // holds this short-lived lock. Wait for an in-flight repair to finish
        // before removing the file, otherwise it could recreate the file after
        // the daemon has already begun shutting down.
        let _repair_lock = match self.repair_lock.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };
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

/// Publish the current in-memory token atomically and with the same
/// permissions/ACLs used at daemon startup. This is deliberately a helper so
/// the startup path and the live repair path cannot drift apart.
fn publish_auth_file(
    path: &AuthPath,
    token: &str,
    diagnostics_client_sid: Option<&str>,
) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| AuthPath::new("."));
    auth_fs::create_dir_all(dir)?;

    let mut temp_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut temp_bytes);
    let temp_path = dir.join(format!(
        ".p2wlan-daemon.diag-auth.{}.tmp",
        hex::encode(temp_bytes)
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
        restrict_auth_file(&temp_path, diagnostics_client_sid)?;
        file.sync_all()?;
        drop(file);

        // Unix rename is an atomic replacement. Windows' std::fs::rename
        // cannot replace an existing file, so remove only the fixed stale
        // path after the new file has been fully written and ACL-checked.
        #[cfg(windows)]
        match auth_fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        auth_fs::rename(&temp_path, path)?;
        if let Err(error) = restrict_auth_file(path, diagnostics_client_sid) {
            let _ = auth_fs::remove_file(path);
            return Err(error);
        }
        #[cfg(unix)]
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = auth_fs::remove_file(&temp_path);
    }
    result
}

fn auth_file_matches(path: &AuthPath, token: &str) -> bool {
    auth_fs::read_to_string(path)
        .map(|value| value.trim() == token)
        .unwrap_or(false)
}

/// Keep the discovery file present for the lifetime of the daemon. Desktop
/// updaters, log cleaners, and account-level cleanup tools can remove files in
/// `~/Library/Logs` while the daemon continues serving diagnostics with the
/// token held in memory. Without this repair loop the UI sees transient 401s
/// (or a missing-token error) even though the dataplane is healthy.
fn spawn_auth_file_repair(
    path: AuthPathBuf,
    token: Zeroizing<String>,
    diagnostics_client_sid: Option<String>,
    repair_lock: DiagnosticsArc<Mutex<()>>,
) -> Option<tokio::task::AbortHandle> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    let task = runtime.spawn(async move {
        let mut interval = tokio::time::interval(AuthRepairDuration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if auth_file_matches(&path, token.as_str()) {
                continue;
            }

            let _repair_lock = match repair_lock.lock() {
                Ok(lock) => lock,
                Err(poisoned) => poisoned.into_inner(),
            };
            if auth_file_matches(&path, token.as_str()) {
                continue;
            }
            if let Err(error) = publish_auth_file(
                &path,
                token.as_str(),
                diagnostics_client_sid.as_deref(),
            ) {
                warn!(
                    "Failed to repair diagnostics auth token file {}: {error}",
                    path.display()
                );
            } else {
                debug!(
                    "Repaired diagnostics auth token file {}",
                    path.display()
                );
            }
        }
    });
    Some(task.abort_handle())
}

#[cfg(unix)]
fn restrict_auth_file(
    path: &AuthPath,
    _diagnostics_client_sid: Option<&str>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = auth_fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    auth_fs::set_permissions(path, permissions)
}

#[cfg(windows)]
fn restrict_auth_file(
    path: &AuthPath,
    diagnostics_client_sid: Option<&str>,
) -> std::io::Result<()> {
    let daemon_sid = current_windows_sid()?;
    let mut grants = vec![
        format!("*{daemon_sid}:F"),
        "*S-1-5-32-544:F".to_string(),
    ];
    if let Some(client_sid) = diagnostics_client_sid.filter(|sid| is_windows_sid(sid)) {
        let grant = format!("*{client_sid}:F");
        if !grants.contains(&grant) {
            grants.push(grant);
        }
    }
    use std::os::windows::process::CommandExt;

    // The daemon is normally launched from the GUI and has no console of its
    // own. CREATE_NO_WINDOW is required here because icacls is a console
    // executable; without it Windows can briefly show a terminal during
    // daemon startup.
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut command = std::process::Command::new("icacls");
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .arg(path.as_os_str())
        .arg("/inheritance:r")
        .arg("/grant:r");
    for grant in &grants {
        command.arg(grant);
    }
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("icacls exited with {status}"),
        ))
    }
}

#[cfg(windows)]
fn current_windows_sid() -> std::io::Result<String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = std::process::Command::new("powershell.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "could not resolve the Windows daemon SID",
        ));
    }
    let sid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if is_windows_sid(&sid) {
        Ok(sid)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows returned an invalid daemon SID",
        ))
    }
}

#[cfg(windows)]
fn is_windows_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    matches!(parts.next(), Some("S"))
        && parts.next().is_some_and(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        && parts.all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}
