async fn start(config_path: &Path) -> Result<(), String> {
    let config = load_config(config_path)?;
    if config.control.auth_token.trim().is_empty() {
        return Err("尚未登录，请先运行 p2wlan login -u <邮箱>".to_string());
    }
    if fetch_status(&status_url(&config)).await.is_ok() {
        println!("p2wlan 已经在运行。");
        return Ok(());
    }

    let args = InternalStartArgs {
        config: absolute_path(config_path)?,
        state_dir: state_dir(),
        daemon: locate_daemon()?,
    };
    if is_root() {
        return start_daemon_as_root(args).await;
    }

    fs::create_dir_all(&args.state_dir)
        .map_err(|error| format!("无法创建运行目录 {}：{error}", args.state_dir.display()))?;
    let current_exe = env::current_exe().map_err(|error| format!("无法定位 p2wlan：{error}"))?;
    println!("需要管理员权限创建 Linux TUN 和路由，正在请求 sudo...");
    let result = Command::new("sudo")
        .arg(current_exe)
        .arg("__start-daemon")
        .arg("--config")
        .arg(&args.config)
        .arg("--state-dir")
        .arg(&args.state_dir)
        .arg("--daemon")
        .arg(&args.daemon)
        .status()
        .map_err(|error| format!("无法执行 sudo：{error}"))?;
    if !result.success() {
        return Err(format!(
            "管理员启动失败（退出码 {}）",
            result.code().unwrap_or(1)
        ));
    }
    Ok(())
}

async fn start_daemon_as_root(args: InternalStartArgs) -> Result<(), String> {
    if !is_root() {
        return Err("内部启动命令必须以 root 运行".to_string());
    }
    let config = load_config(&args.config)?;
    let url = status_url(&config);
    if fetch_status(&url).await.is_ok() {
        println!("p2wlan 已经在运行。");
        return Ok(());
    }

    fs::create_dir_all(&args.state_dir)
        .map_err(|error| format!("无法创建运行目录 {}：{error}", args.state_dir.display()))?;
    let log_path = args.state_dir.join("p2wlan-daemon.log");
    let pid_path = args.state_dir.join("p2wlan-daemon.pid");
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("无法打开日志 {}：{error}", log_path.display()))?;
    make_world_readable(&log)?;

    let mut command = Command::new(&args.daemon);
    command
        .arg("--config")
        .arg(&args.config)
        .arg("--diagnostics-bind")
        .arg(&config.diagnostics.bind)
        .arg("--log-file")
        .arg(&log_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("无法启动 {}：{error}", args.daemon.display()))?;
    fs::write(&pid_path, child.id().to_string())
        .map_err(|error| format!("无法写入 PID 文件：{error}"))?;

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(exit) = child
            .try_wait()
            .map_err(|error| format!("无法检查 daemon 状态：{error}"))?
        {
            return Err(format!(
                "daemon 启动后立即退出（{exit}）。请运行 p2wlan logs 查看原因"
            ));
        }
        if let Ok(snapshot) = fetch_status(&url).await {
            println!(
                "p2wlan 已启动：{}（PID {}）",
                snapshot
                    .get("virtual_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("等待地址分配"),
                child.id()
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err("daemon 已启动，但 30 秒内诊断端点没有就绪。请运行 p2wlan logs".to_string())
}

async fn stop(config_path: &Path) -> Result<(), String> {
    let config = load_config(config_path)?;
    let url = format!(
        "http://{}/shutdown",
        normalized_diagnostics_bind(&config.diagnostics.bind)
    );
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|error| error.to_string())?
        .post(url)
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            println!("已发送停止请求。");
            Ok(())
        }
        _ => {
            let pid_path = state_dir().join("p2wlan-daemon.pid");
            let Some(pid) = verified_recorded_daemon(&pid_path)? else {
                println!("p2wlan 未运行。");
                return Ok(());
            };
            println!("诊断端点不可访问，正在向已校验的 daemon PID {pid} 发送 SIGTERM...");
            terminate_daemon(pid)?;
            Ok(())
        }
    }
}
