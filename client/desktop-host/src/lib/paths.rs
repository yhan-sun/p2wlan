pub fn config_path_from_base(base: impl AsRef<Path>) -> PathBuf {
    base.as_ref().join("p2wlan").join("p2wlan-config.json")
}

pub fn default_config_path() -> PathBuf {
    let base = dirs::config_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    config_path_from_base(base)
}

pub fn macos_log_dir_from_home(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join("Library").join("Logs").join("p2wlan")
}

pub fn linux_log_dir_from_home(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join(".p2wlan").join("logs")
}

pub fn windows_log_dir_from_local_app_data(local_app_data: impl AsRef<Path>) -> PathBuf {
    local_app_data.as_ref().join("p2wlan").join("logs")
}

pub fn default_log_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        dirs::home_dir()
            .map(macos_log_dir_from_home)
            .unwrap_or_else(|| PathBuf::from("."))
    } else if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA")
            .map(windows_log_dir_from_local_app_data)
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        dirs::home_dir()
            .map(linux_log_dir_from_home)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

pub fn pid_path_from_log_dir(log_dir: impl AsRef<Path>) -> PathBuf {
    log_dir.as_ref().join("p2wlan-daemon.pid")
}

pub fn endpoint_path_from_log_dir(log_dir: impl AsRef<Path>) -> PathBuf {
    log_dir.as_ref().join("p2wlan-daemon.endpoint")
}

pub fn recent_daemon_log_lines(path: impl AsRef<Path>, max_lines: usize) -> Result<Vec<String>> {
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path.as_ref()).map_err(|error| {
        DesktopHostError::new(
            DesktopHostErrorKind::Io,
            "Failed to read daemon log file",
            true,
        )
        .with_detail(error.to_string())
    })?;
    let lines = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].to_vec())
}

fn invalid_url(message: impl Into<String>) -> DesktopHostError {
    DesktopHostError::new(DesktopHostErrorKind::InvalidDiagnosticsUrl, message, true)
}
