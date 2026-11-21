fn prepare_product_windows_environment() -> std::io::Result<()> {
    use p2pnet_daemon::windows_service_paths::ServicePaths;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::LibraryLoader::{
        SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let paths = ServicePaths::resolve()?;
    paths.validate_installation()?;
    let mut directory = vec![0; 32_767];
    let length =
        unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
    if length == 0 || length >= directory.len() {
        return Err(std::io::Error::last_os_error());
    }
    let system = PathBuf::from(OsString::from_wide(&directory[..length]));
    std::env::set_current_dir(&system)?;
    let path = std::env::join_paths([&system, &system.join("WindowsPowerShell/v1.0")])
        .map_err(std::io::Error::other)?;
    std::env::set_var("PATH", path);
    if unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    std::env::set_var("P2WLAN_WINTUN_DLL", paths.app.join("wintun.dll"));
    std::env::set_var("P2WLAN_STRICT_WINTUN_DLL", "1");
    std::env::remove_var("P2WLAN_DISABLE_TUN");
    Ok(())
}

fn validate_product_windows_profile(cli: &Cli) -> p2pnet_daemon::Result<()> {
    use p2pnet_daemon::windows_service_paths::ServicePaths;
    let paths = ServicePaths::resolve().map_err(windows_profile_error)?;
    let log = paths.root.join("p2wlan-daemon.log");
    if cli.config != paths.config() || cli.log_file.as_ref() != Some(&log) {
        return Err(DaemonError::Config(
            "Windows service requires the protected ProgramData profile and log path".into(),
        ));
    }
    paths.check_profile_root().map_err(windows_profile_error)?;
    for entry in std::fs::read_dir(&paths.root).map_err(windows_profile_error)? {
        let path = entry.map_err(windows_profile_error)?.path();
        paths
            .check_private_file(&path)
            .map_err(windows_profile_error)?;
    }
    paths
        .check_private_file(&cli.config)
        .map_err(windows_profile_error)
}

fn prepare_windows_managed_identity(
    config: &Config,
) -> p2pnet_daemon::Result<Option<p2pnet_daemon::WindowsIdentityLease>> {
    use p2pnet_daemon::incarnation::{
        reserve_boot_incarnation_for_machine_profile, INCARNATION_FILE_NAME,
    };
    use p2pnet_daemon::{
        same_windows_device, windows_service_paths::ServicePaths, WindowsIdentityLease,
    };

    if config.network.manual {
        return Ok(None);
    }
    let lease = WindowsIdentityLease::acquire(config).map_err(windows_profile_error)?;
    let machine = || {
        let paths = ServicePaths::resolve().ok()?;
        let path = paths.config();
        paths.check_profile_root().ok()?;
        paths.check_private_file(&path).ok()?;
        let mut machine = Config::load_from_file(&path).ok()?;
        if !same_windows_device(config, &machine) {
            return None;
        }
        machine.config_path = Some(path);
        Some((paths, machine))
    };
    if let Some((paths, machine)) = machine() {
        paths
            .check_private_file(&paths.root.join("incarnation.lock"))
            .map_err(windows_profile_error)?;
        paths
            .check_private_file(&paths.root.join(INCARNATION_FILE_NAME))
            .map_err(windows_profile_error)?;
        if reserve_boot_incarnation_for_machine_profile(config, &machine).is_none() {
            return Err(DaemonError::Config(
                "Windows device registration counter could not be reserved".into(),
            ));
        }
    } else if product_windows_service() {
        return Err(DaemonError::Config(
            "Windows service has no matching enrolled machine profile".into(),
        ));
    }
    Ok(Some(lease))
}

fn windows_profile_error(error: std::io::Error) -> DaemonError {
    DaemonError::Config(format!("Windows device profile: {error}"))
}
