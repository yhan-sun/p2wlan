fn default_config_path() -> PathBuf {
    if let Some(path) = env::var_os("P2WLAN_CONFIG") {
        return PathBuf::from(path);
    }
    config_dir().join("p2wlan-config.json")
}

fn config_dir() -> PathBuf {
    if let Some(path) = env::var_os("P2WLAN_HOME") {
        return PathBuf::from(path);
    }
    if env::var_os("SUDO_USER").is_none() {
        if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(path).join("p2wlan");
        }
    }
    user_home().join(".config").join("p2wlan")
}

fn state_dir() -> PathBuf {
    if let Some(path) = env::var_os("P2WLAN_STATE_DIR") {
        return PathBuf::from(path);
    }
    if env::var_os("SUDO_USER").is_none() {
        if let Some(path) = env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(path).join("p2wlan");
        }
    }
    user_home().join(".local").join("state").join("p2wlan")
}

fn user_home() -> PathBuf {
    if let Ok(user) = env::var("SUDO_USER") {
        if user != "root" {
            if let Ok(mut passwd) = File::open("/etc/passwd") {
                let mut contents = String::new();
                if passwd.read_to_string(&mut contents).is_ok() {
                    for line in contents.lines() {
                        let fields = line.split(':').collect::<Vec<_>>();
                        if fields.len() >= 6 && fields[0] == user {
                            return PathBuf::from(fields[5]);
                        }
                    }
                }
            }
        }
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn locate_daemon() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("P2WLAN_DAEMON") {
        return absolute_path(Path::new(&path));
    }
    let sibling = env::current_exe()
        .map_err(|error| format!("无法定位当前程序：{error}"))?
        .with_file_name("p2wlan-daemon");
    if sibling.is_file() {
        return Ok(sibling);
    }
    // The daemon was renamed p2pnet-daemon -> p2wlan-daemon in v0.1.67.
    // Installations updated from a CLI released before the rename keep the
    // legacy binary name, so fall back to it before giving up.
    let legacy_sibling = env::current_exe()
        .map_err(|error| format!("无法定位当前程序：{error}"))?
        .with_file_name("p2pnet-daemon");
    if legacy_sibling.is_file() {
        return Ok(legacy_sibling);
    }
    find_in_path("p2wlan-daemon")
        .or_else(|| find_in_path("p2pnet-daemon"))
        .ok_or_else(|| {
            "找不到 p2wlan-daemon；请保持它与 p2wlan 位于同一目录，或设置 P2WLAN_DAEMON".to_string()
        })
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|path| path.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("无法解析路径 {}：{error}", path.display()))
    }
}

fn reject_sudo_config_write() -> Result<(), String> {
    if is_root() && env::var_os("SUDO_USER").is_some() {
        return Err(
            "login/logout/config 请不要使用 sudo；只有 p2wlan up 需要管理员权限".to_string(),
        );
    }
    Ok(())
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn verified_recorded_daemon(pid_path: &Path) -> Result<Option<i32>, String> {
    let Ok(raw) = fs::read_to_string(pid_path) else {
        return Ok(None);
    };
    let Ok(pid) = raw.trim().parse::<i32>() else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return Ok(None);
        }
        let command_line = fs::read(format!("/proc/{pid}/cmdline"))
            .unwrap_or_default()
            .split(|byte| *byte == 0)
            .filter_map(|part| std::str::from_utf8(part).ok())
            .collect::<Vec<_>>()
            .join(" ");
        if !command_line.contains("p2wlan-daemon") && !command_line.contains("p2pnet-daemon") {
            return Err(format!(
                "PID 文件 {} 指向的不是 p2wlan-daemon，拒绝结束进程",
                pid_path.display()
            ));
        }
        Ok(Some(pid))
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Ok(None)
    }
}

#[cfg(unix)]
fn terminate_daemon(pid: i32) -> Result<(), String> {
    if is_root() {
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            println!("已发送停止请求。");
            return Ok(());
        }
        return Err(format!(
            "无法结束 daemon PID {pid}：{}",
            io::Error::last_os_error()
        ));
    }
    let status = Command::new("sudo")
        .arg("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .map_err(|error| format!("无法执行 sudo kill：{error}"))?;
    if !status.success() {
        return Err(format!("无法结束 daemon PID {pid}（{status}）"));
    }
    println!("已发送停止请求。");
    Ok(())
}

#[cfg(not(unix))]
fn terminate_daemon(_pid: i32) -> Result<(), String> {
    Err("通过 PID 文件停止 daemon 仅支持 Unix；请使用诊断端点".to_string())
}

fn make_world_readable(file: &File) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file
            .metadata()
            .map_err(|error| format!("无法读取日志权限：{error}"))?
            .permissions();
        permissions.set_mode(0o644);
        file.set_permissions(permissions)
            .map_err(|error| format!("无法设置日志权限：{error}"))?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}
