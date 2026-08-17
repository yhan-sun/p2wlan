fn stop_daemon() -> Result<(), Box<dyn Error>> {
    let shutdown_url = shutdown_url()?;
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    let mut request = client.post(shutdown_url);
    // The diagnostics mutation endpoint requires the daemon's per-process
    // auth token (written by the daemon next to its log file at startup).
    if let Some(token) = read_diagnostics_auth_token() {
        request = request.bearer_auth(token);
    }
    let response = request.send()?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("daemon returned HTTP {}", response.status()).into())
    }
}

/// Read the daemon's per-process diagnostics auth token from the file the
/// daemon writes at startup next to its log file. `None` when the daemon is
/// not running or has not published one yet. Checks both the tray's log dir
/// and the Flutter client's log dir (they differ on Linux).
fn read_diagnostics_auth_token() -> Option<String> {
    let mut candidates = vec![p2wlan_desktop_host::default_log_dir()];
    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        candidates.push(home.join(".local/state/p2wlan"));
    }
    for log_dir in candidates {
        let path = log_dir.join("p2wlan-daemon.diag-auth");
        if let Ok(value) = fs::read_to_string(&path) {
            let token = value.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn shutdown_url() -> Result<String, Box<dyn Error>> {
    let status_url = p2wlan_desktop_host::normalize_diagnostics_url(STATUS_URL)?;
    let mut parsed = reqwest::Url::parse(&status_url)?;
    parsed.set_path("/shutdown");
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn start_daemon() -> Result<(), Box<dyn Error>> {
    if query_daemon_state().running {
        return Ok(());
    }
    let daemon = locate_daemon_binary().ok_or("p2wlan-daemon not found")?;
    let config_path = p2wlan_desktop_host::default_config_path();
    let log_dir = p2wlan_desktop_host::default_log_dir();
    let log_path = log_dir.join("p2wlan-daemon.log");
    let pid_path = p2wlan_desktop_host::pid_path_from_log_dir(&log_dir);
    let bind = p2wlan_desktop_host::diagnostics_bind_from_url(STATUS_URL)?;
    let managed = config_has_token(&config_path);

    fs::create_dir_all(&log_dir)?;
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut args = vec![
        "--config".to_string(),
        config_path.display().to_string(),
        "--diagnostics-bind".to_string(),
        bind,
        "--log-file".to_string(),
        log_path.display().to_string(),
    ];
    if managed {
        args.push("--managed".to_string());
    } else {
        args.push("--manual".to_string());
    }

    start_daemon_platform(&daemon, &args, &config_path, &log_dir, &log_path, &pid_path)
}

#[cfg(target_os = "macos")]
fn start_daemon_platform(
    daemon: &Path,
    args: &[String],
    config_path: &Path,
    log_dir: &Path,
    log_path: &Path,
    pid_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let owner = user_owner_for_paths();
    let repair = owner.as_ref().map(|owner| {
        format!(
            "owner={}; group=\"$(/usr/bin/id -gn \"$owner\" 2>/dev/null || /bin/echo staff)\"; /usr/sbin/chown -R \"$owner:$group\" {} {} >/dev/null 2>&1 || true; ",
            shell_quote(owner),
            shell_quote(&config_dir.display().to_string()),
            shell_quote(&log_dir.display().to_string())
        )
    });
    let repair_before = repair.clone().unwrap_or_default();
    let repair_after = repair
        .map(|repair| format!("; /bin/sleep 1; {repair}"))
        .unwrap_or_default();
    let args = args
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let command = format!(
        "mkdir -p {config_dir} {log_dir}; {repair_before}: > {log}; chmod 644 {log}; \
         if [ -f {pid} ]; then oldpid=\"$(/bin/cat {pid} 2>/dev/null || true)\"; \
         case \"$oldpid\" in \"\"|*[!0-9]*) ;; *) \
         if /bin/ps -p \"$oldpid\" -o command= 2>/dev/null | /usr/bin/grep -q p2wlan-daemon; then \
         /bin/kill \"$oldpid\" >/dev/null 2>&1 || true; /bin/sleep 1; fi ;; esac; fi; \
         (P2WLAN_DAEMON_BIN={daemon} {daemon} {args} >> {log} 2>&1 < /dev/null & echo $! > {pid}){repair_after}",
        config_dir = shell_quote(&config_dir.display().to_string()),
        log_dir = shell_quote(&log_dir.display().to_string()),
        log = shell_quote(&log_path.display().to_string()),
        pid = shell_quote(&pid_path.display().to_string()),
        daemon = shell_quote(&daemon.display().to_string()),
    );
    let script = format!(
        "do shell script \"{}\" with administrator privileges with prompt \"{}\"",
        applescript_quote(&command),
        applescript_quote("p2wlan-tray needs administrator permission to start p2wlan-daemon.")
    );
    let output = Command::new("osascript").arg("-e").arg(script).output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.contains("-128") {
            "administrator authorization cancelled".into()
        } else if stderr.is_empty() {
            "administrator launch failed".into()
        } else {
            stderr.into()
        })
    }
}

#[cfg(not(target_os = "macos"))]
fn start_daemon_platform(
    daemon: &Path,
    args: &[String],
    _config_path: &Path,
    _log_dir: &Path,
    log_path: &Path,
    _pid_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    Command::new(daemon)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log.try_clone()?))
        .stderr(std::process::Stdio::from(log))
        .spawn()?;
    Ok(())
}

fn config_has_token(path: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    value
        .get("control")
        .and_then(|control| control.get("auth_token"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|token| !token.trim().is_empty())
}

fn locate_daemon_binary() -> Option<PathBuf> {
    if let Some(path) = env::var_os("P2WLAN_DAEMON_BIN").map(PathBuf::from) {
        if path.exists() {
            return Some(path);
        }
    }

    let mut candidates = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(DAEMON_NAME));
            if let Some(contents) = dir.parent() {
                candidates.push(contents.join("Resources").join(DAEMON_NAME));
            }
        }
    }
    if let Ok(current_dir) = env::current_dir() {
        let mut dir = current_dir.as_path();
        for _ in 0..6 {
            candidates.push(dir.join("target").join("debug").join(DAEMON_NAME));
            candidates.push(dir.join("target").join("release").join(DAEMON_NAME));
            let Some(parent) = dir.parent() else {
                break;
            };
            dir = parent;
        }
    }
    if let Some(root) = find_repo_root() {
        candidates.push(root.join("target").join("debug").join(DAEMON_NAME));
        candidates.push(root.join("target").join("release").join(DAEMON_NAME));
    }

    candidates
        .into_iter()
        .find(|path| path.exists())
        .or_else(which_daemon)
}

fn which_daemon() -> Option<PathBuf> {
    let command = if cfg!(windows) { "where" } else { "which" };
    let output = Command::new(command).arg(DAEMON_NAME).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(PathBuf::from)
}
