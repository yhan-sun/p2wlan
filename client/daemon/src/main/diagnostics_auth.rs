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
    token: Zeroizing<String>,
    repair_abort: Option<tokio::task::AbortHandle>,
    repair_lock: DiagnosticsArc<Mutex<Option<DiagnosticsDiscoveryLock>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DiagnosticsAuthOwner {
    #[cfg(unix)]
    uid: libc::uid_t,
    #[cfg(unix)]
    gid: libc::gid_t,
}

#[cfg(unix)]
fn diagnostics_owner_for_euid(
    euid: libc::uid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Option<DiagnosticsAuthOwner> {
    (euid == 0).then_some(DiagnosticsAuthOwner { uid, gid })
}

fn capture_diagnostics_auth_owner(dir: &AuthPath) -> std::io::Result<Option<DiagnosticsAuthOwner>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = auth_fs::metadata(dir)?;
        // The GUI creates this canonical directory before elevation. Never
        // infer its owner from root's HOME or another process environment.
        Ok(diagnostics_owner_for_euid(
            unsafe { libc::geteuid() },
            metadata.uid(),
            metadata.gid(),
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(None)
    }
}

/// The discovery namespace has one publisher even when configuration paths
/// differ. Never unlink this lock file: another process may be waiting on it.
struct DiagnosticsDiscoveryLock {
    path: AuthPathBuf,
    file: auth_fs::File,
    #[cfg(unix)]
    directory: auth_fs::File,
}

impl DiagnosticsDiscoveryLock {
    fn acquire(
        dir: &AuthPath,
        owner: Option<DiagnosticsAuthOwner>,
        diagnostics_client_sid: Option<&str>,
    ) -> std::io::Result<Self> {
        let path = dir.join("p2wlan-daemon.diag-auth.lock");
        #[cfg(unix)]
        let directory = open_auth_directory(dir, false)?;
        #[cfg(unix)]
        validate_auth_directory_owner(&directory, owner)?;
        #[cfg(not(unix))]
        let mut options = auth_fs::OpenOptions::new();
        #[cfg(not(unix))]
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        let file = open_auth_file_at(
            &directory,
            c"p2wlan-daemon.diag-auth.lock",
            libc::O_RDWR | libc::O_CREAT,
        )?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Keep the fixed lock inode in place while allowing another
            // process to open it and receive the explicit lock conflict.
            options.share_mode(0x00000001 | 0x00000002);
        }
        #[cfg(not(unix))]
        let file = options.open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "diagnostics discovery lock is not a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if file.metadata()?.nlink() != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "diagnostics discovery lock has unexpected hard links",
                ));
            }
        }
        fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("diagnostics discovery directory already owned or unavailable: {error}"),
            )
        })?;
        let lock = Self {
            path,
            file,
            #[cfg(unix)]
            directory,
        };
        if !lock.is_current() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "diagnostics discovery lock changed while acquiring ownership",
            ));
        }
        // A failed contender must not change the active publisher's ACL/owner.
        #[cfg(unix)]
        {
            restrict_auth_directory(&lock.directory, owner)?;
            restrict_auth_file(&lock.file, owner)?;
        }
        #[cfg(windows)]
        restrict_auth_file(&lock.path, diagnostics_client_sid)?;
        #[cfg(unix)]
        let _ = diagnostics_client_sid;
        #[cfg(windows)]
        let _ = owner;
        Ok(lock)
    }

    fn is_current(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Some(dir) = self.path.parent() else {
                return false;
            };
            let Ok(current_directory) = open_auth_directory(dir, false) else {
                return false;
            };
            let (Ok(current_dir), Ok(held_dir)) =
                (current_directory.metadata(), self.directory.metadata())
            else {
                return false;
            };
            if current_dir.dev() != held_dir.dev() || current_dir.ino() != held_dir.ino() {
                return false;
            }
            let Ok(current) = open_auth_file_at(
                &self.directory,
                c"p2wlan-daemon.diag-auth.lock",
                libc::O_RDONLY,
            ) else {
                return false;
            };
            let (Ok(current), Ok(held)) = (current.metadata(), self.file.metadata()) else {
                return false;
            };
            current.is_file()
                && current.nlink() == 1
                && current.dev() == held.dev()
                && current.ino() == held.ino()
        }
        #[cfg(not(unix))]
        {
            // Windows denies delete sharing for this held file handle.
            self.file.metadata().is_ok() && self.path.is_file()
        }
    }

    fn auth_matches(&self, token: &str) -> bool {
        #[cfg(unix)]
        {
            open_auth_file_at(&self.directory, c"p2wlan-daemon.diag-auth", libc::O_RDONLY)
                .is_ok_and(|file| auth_file_contents_match(file, token))
        }
        #[cfg(not(unix))]
        {
            auth_file_matches(&self.path.with_file_name("p2wlan-daemon.diag-auth"), token)
        }
    }

    fn remove_auth_file(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    c"p2wlan-daemon.diag-auth".as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            auth_fs::remove_file(self.path.with_file_name("p2wlan-daemon.diag-auth"))
        }
    }

    fn ensure_current(
        &mut self,
        owner: Option<DiagnosticsAuthOwner>,
        diagnostics_client_sid: Option<&str>,
    ) -> std::io::Result<()> {
        if self.is_current() {
            #[cfg(unix)]
            validate_auth_directory_owner(&self.directory, owner)?;
            return Ok(());
        }
        let dir = self.path.parent().unwrap_or_else(|| AuthPath::new("."));
        #[cfg(unix)]
        {
            // Recreate only the exact leaf. Missing or redirected ancestors
            // require a fresh launcher preparation, never a recursive repair.
            open_auth_directory(dir, true)?;
        }
        #[cfg(not(unix))]
        auth_fs::create_dir_all(dir)?;
        // External cleanup may unlink the whole directory. The old inode's
        // lock grants no authority over a recreated directory: reacquire the
        // same namespace without waiting before publishing anything there.
        *self = Self::acquire(dir, owner, diagnostics_client_sid)?;
        Ok(())
    }
}

#[cfg(unix)]
fn auth_component_name(value: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(value.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid diagnostics path")
    })
}

#[cfg(unix)]
fn open_auth_file_at(
    directory: &auth_fs::File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> std::io::Result<auth_fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // openat returned an owned descriptor; File closes it on every exit path.
    Ok(unsafe { auth_fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_auth_directory(dir: &AuthPath, create_leaf: bool) -> std::io::Result<auth_fs::File> {
    use std::os::fd::AsRawFd;
    use std::path::Component;
    if !dir.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "diagnostics repair requires its canonical absolute directory",
        ));
    }
    let mut directory = auth_fs::File::open("/")?;
    let mut parts = dir.components().peekable();
    while let Some(part) = parts.next() {
        let name = match part {
            Component::RootDir => continue,
            Component::Normal(name) => auth_component_name(name)?,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "diagnostics directory is not canonical",
                ));
            }
        };
        let opened = open_auth_file_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY);
        directory = match opened {
            Ok(opened) => opened,
            Err(error)
                if create_leaf
                    && parts.peek().is_none()
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                let result = unsafe {
                    libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700 as libc::mode_t)
                };
                if result != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                open_auth_file_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY)?
            }
            Err(error) => return Err(error),
        };
    }
    Ok(directory)
}

#[cfg(unix)]
fn validate_auth_directory_owner(
    directory: &auth_fs::File,
    owner: Option<DiagnosticsAuthOwner>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let current = directory.metadata()?;
    let euid = unsafe { libc::geteuid() };
    let expected_uid = owner.map_or(euid, |owner| owner.uid);
    if !current.is_dir() || (current.uid() != expected_uid && current.uid() != euid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "diagnostics directory belongs to a different user",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_auth_directory(
    directory: &auth_fs::File,
    owner: Option<DiagnosticsAuthOwner>,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    validate_auth_directory_owner(directory, owner)?;
    if let Some(owner) = owner {
        let current = directory.metadata()?;
        if (current.uid(), current.gid()) != (owner.uid, owner.gid)
            && unsafe { libc::fchown(directory.as_raw_fd(), owner.uid, owner.gid) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    directory.set_permissions(auth_fs::Permissions::from_mode(0o700))
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
        let dir = auth_fs::canonicalize(&dir).map_err(|error| {
            DaemonError::Config(format!(
                "failed to resolve diagnostics auth directory: {error}"
            ))
        })?;
        let owner = capture_diagnostics_auth_owner(&dir).map_err(|error| {
            DaemonError::Config(format!(
                "failed to inspect diagnostics auth directory: {error}"
            ))
        })?;
        let discovery_lock = DiagnosticsDiscoveryLock::acquire(&dir, owner, diagnostics_client_sid)
            .map_err(|error| {
                DaemonError::Config(format!("failed to own diagnostics auth directory: {error}"))
            })?;

        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = Zeroizing::new(hex::encode(bytes));
        let path = dir.join("p2wlan-daemon.diag-auth");
        let result = publish_auth_file(
            &discovery_lock,
            &path,
            token.as_str(),
            owner,
            diagnostics_client_sid,
        );

        if let Err(error) = result {
            return Err(DaemonError::Config(format!(
                "failed to publish diagnostics auth file {}: {error}",
                path.display()
            )));
        }

        config.diagnostics.auth_token = Some(token.to_string());
        config.diagnostics.auth_token_path = Some(path.clone());
        let repair_lock = DiagnosticsArc::new(Mutex::new(Some(discovery_lock)));
        let repair_abort = spawn_auth_file_repair(
            path.clone(),
            token.clone(),
            owner,
            diagnostics_client_sid.map(ToOwned::to_owned),
            repair_lock.clone(),
        );
        Ok(Some(Self {
            path,
            token,
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
        let mut repair_lock = match self.repair_lock.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };
        let owns_current_file = repair_lock
            .as_ref()
            .is_some_and(|lock| lock.is_current() && lock.auth_matches(self.token.as_str()));
        if !owns_current_file {
            // Never reacquire a missing lock merely to remove a successor's
            // discovery file. The aborted task also observes this empty slot.
            repair_lock.take();
            return;
        }
        let Some(lock) = repair_lock.as_ref() else {
            return;
        };
        match lock.remove_auth_file() {
            Ok(()) => info!(
                "Removed diagnostics auth token file {}",
                self.path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!(
                "Failed to remove diagnostics auth token file {}: {error}",
                self.path.display()
            ),
        }
        repair_lock.take();
    }
}

/// Publish the current in-memory token atomically and with the same
/// permissions/ACLs used at daemon startup. This is deliberately a helper so
/// the startup path and the live repair path cannot drift apart.
fn publish_auth_file(
    discovery_lock: &DiagnosticsDiscoveryLock,
    path: &AuthPath,
    token: &str,
    owner: Option<DiagnosticsAuthOwner>,
    diagnostics_client_sid: Option<&str>,
) -> std::io::Result<()> {
    if path
        != discovery_lock
            .path
            .with_file_name("p2wlan-daemon.diag-auth")
        || !discovery_lock.is_current()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "diagnostics discovery ownership changed before publication",
        ));
    }
    #[cfg(unix)]
    validate_auth_directory_owner(&discovery_lock.directory, owner)?;
    let dir = path.parent().unwrap_or_else(|| AuthPath::new("."));
    let mut temp_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut temp_bytes);
    let temp_path = dir.join(format!(
        ".p2wlan-daemon.diag-auth.{}.tmp",
        hex::encode(temp_bytes)
    ));

    #[cfg(unix)]
    let temp_name = auth_component_name(temp_path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing auth file name")
    })?)?;
    let result = (|| -> std::io::Result<()> {
        use std::io::Write;

        #[cfg(unix)]
        let mut file = open_auth_file_at(
            &discovery_lock.directory,
            &temp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        #[cfg(not(unix))]
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(token.as_bytes())?;
        file.flush()?;
        #[cfg(unix)]
        restrict_auth_file(&file, owner)?;
        #[cfg(windows)]
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
        if !discovery_lock.is_current() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "diagnostics discovery ownership changed during publication",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = discovery_lock.directory.as_raw_fd();
            // Both names are relative to the held directory, so replacement
            // of an ancestor cannot redirect this write into a successor.
            if unsafe {
                libc::renameat(
                    fd,
                    temp_name.as_ptr(),
                    fd,
                    c"p2wlan-daemon.diag-auth".as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        #[cfg(not(unix))]
        auth_fs::rename(&temp_path, path)?;
        #[cfg(windows)]
        if let Err(error) = restrict_auth_file(path, diagnostics_client_sid) {
            let _ = auth_fs::remove_file(path);
            return Err(error);
        }
        #[cfg(unix)]
        discovery_lock.directory.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // The random temporary name belongs to this publication only.
            unsafe {
                libc::unlinkat(discovery_lock.directory.as_raw_fd(), temp_name.as_ptr(), 0);
            }
        }
        #[cfg(not(unix))]
        let _ = auth_fs::remove_file(&temp_path);
    }
    #[cfg(unix)]
    let _ = diagnostics_client_sid;
    #[cfg(windows)]
    let _ = owner;
    result
}

#[cfg(any(test, not(unix)))]
fn auth_file_matches(path: &AuthPath, token: &str) -> bool {
    let mut options = auth_fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let Ok(file) = options.open(path) else {
        return false;
    };
    auth_file_contents_match(file, token)
}

fn auth_file_contents_match(file: auth_fs::File, token: &str) -> bool {
    use std::io::Read;
    const MAX_AUTH_FILE_BYTES: u64 = 4096;
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file() || metadata.len() > MAX_AUTH_FILE_BYTES {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x00000400 != 0 {
            return false; // FILE_ATTRIBUTE_REPARSE_POINT
        }
    }
    let mut value = Zeroizing::new(String::new());
    file.take(MAX_AUTH_FILE_BYTES + 1)
        .read_to_string(&mut value)
        .is_ok()
        && value.len() as u64 <= MAX_AUTH_FILE_BYTES
        && value.trim() == token
}

#[derive(Debug, PartialEq, Eq)]
enum DiagnosticsAuthRepair {
    Closed,
    Unchanged,
    Repaired,
}

fn repair_auth_file_if_needed(
    discovery_lock: &mut Option<DiagnosticsDiscoveryLock>,
    path: &AuthPath,
    token: &str,
    owner: Option<DiagnosticsAuthOwner>,
    diagnostics_client_sid: Option<&str>,
) -> std::io::Result<DiagnosticsAuthRepair> {
    let Some(discovery_lock) = discovery_lock.as_mut() else {
        // A task that was blocked on the mutex before Drop must not revive
        // the namespace after the guard has permanently closed it.
        return Ok(DiagnosticsAuthRepair::Closed);
    };
    discovery_lock.ensure_current(owner, diagnostics_client_sid)?;
    if discovery_lock.auth_matches(token) {
        return Ok(DiagnosticsAuthRepair::Unchanged);
    }
    publish_auth_file(discovery_lock, path, token, owner, diagnostics_client_sid)?;
    Ok(DiagnosticsAuthRepair::Repaired)
}

/// Keep the discovery file present for the lifetime of the daemon. Desktop
/// updaters, log cleaners, and account-level cleanup tools can remove files in
/// `~/Library/Logs` while the daemon continues serving diagnostics with the
/// token held in memory. Without this repair loop the UI sees transient 401s
/// (or a missing-token error) even though the dataplane is healthy.
fn spawn_auth_file_repair(
    path: AuthPathBuf,
    token: Zeroizing<String>,
    owner: Option<DiagnosticsAuthOwner>,
    diagnostics_client_sid: Option<String>,
    repair_lock: DiagnosticsArc<Mutex<Option<DiagnosticsDiscoveryLock>>>,
) -> Option<tokio::task::AbortHandle> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    let task = runtime.spawn(async move {
        let mut interval = tokio::time::interval(AuthRepairDuration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut retry_delay = AuthRepairDuration::from_millis(100);
        let mut retry_at = tokio::time::Instant::now();
        let mut warn_at = retry_at;
        loop {
            interval.tick().await;
            if tokio::time::Instant::now() < retry_at {
                continue;
            }
            let result = {
                let mut repair_lock = match repair_lock.lock() {
                    Ok(lock) => lock,
                    Err(poisoned) => poisoned.into_inner(),
                };
                repair_auth_file_if_needed(
                    &mut repair_lock,
                    &path,
                    token.as_str(),
                    owner,
                    diagnostics_client_sid.as_deref(),
                )
            };
            match result {
                Ok(DiagnosticsAuthRepair::Closed) => return,
                Ok(state) => {
                    retry_delay = AuthRepairDuration::from_millis(100);
                    retry_at = tokio::time::Instant::now();
                    if state == DiagnosticsAuthRepair::Repaired {
                        debug!("Repaired diagnostics auth token file {}", path.display());
                    }
                }
                Err(error) => {
                    let now = tokio::time::Instant::now();
                    retry_at = now + retry_delay;
                    retry_delay = (retry_delay * 2).min(AuthRepairDuration::from_secs(5));
                    if now >= warn_at {
                        warn!(
                            "Failed to repair diagnostics auth token file {}: {error}",
                            path.display()
                        );
                        warn_at = now + AuthRepairDuration::from_secs(30);
                    }
                }
            }
        }
    });
    Some(task.abort_handle())
}

#[cfg(unix)]
fn restrict_auth_file(
    file: &auth_fs::File,
    owner: Option<DiagnosticsAuthOwner>,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if let Some(owner) = owner {
        let current = file.metadata()?;
        if (current.uid(), current.gid()) != (owner.uid, owner.gid) {
            // Only prepare under euid 0 produces an owner override. Operate
            // on the already-open temporary file, never a replaceable path.
            if unsafe { libc::fchown(file.as_raw_fd(), owner.uid, owner.gid) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    file.set_permissions(auth_fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn restrict_auth_file(
    path: &AuthPath,
    diagnostics_client_sid: Option<&str>,
) -> std::io::Result<()> {
    let daemon_sid = current_windows_sid()?;
    let mut grants = vec![format!("*{daemon_sid}:F"), "*S-1-5-32-544:F".to_string()];
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
        && parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        && parts.all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}
