async fn update(config_path: &Path, args: UpdateArgs) -> Result<(), String> {
    let arch = linux_release_arch()?;
    let install_dir = args
        .install_dir
        .or_else(|| env::var_os("P2WLAN_INSTALL_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_DIR));
    let release = fetch_github_release(&args.repo, args.version.as_deref()).await?;
    let asset_name = format!("p2wlan-linux-{arch}-cli.tar.gz");
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| format!("release {} 没有找到资产 {asset_name}", release.tag_name))?;

    println!("当前版本：{}", env!("CARGO_PKG_VERSION"));
    println!("目标版本：{}", release.tag_name);
    println!("安装目录：{}", install_dir.display());
    if let Some(url) = &release.html_url {
        println!("Release：{url}");
    }

    let target_version = release.tag_name.trim_start_matches('v');
    if args.version.is_none() && target_version == env!("CARGO_PKG_VERSION") {
        println!("已经是最新版本。");
        return Ok(());
    }
    if args.dry_run {
        println!("dry-run：将下载并安装 {}", asset.name);
        return Ok(());
    }

    let daemon_running = match load_config(config_path) {
        Ok(config) => fetch_status(&status_url(&config)).await.is_ok(),
        Err(_) => false,
    };

    let work_dir = temp_update_dir()?;
    fs::create_dir_all(&work_dir)
        .map_err(|error| format!("无法创建临时目录 {}：{error}", work_dir.display()))?;
    let archive_path = work_dir.join(&asset.name);
    download_to_file(&asset.browser_download_url, &archive_path).await?;
    extract_tar_gz(&archive_path, &work_dir)?;

    let package_dir = work_dir.join(format!("p2wlan-linux-{arch}-cli"));
    install_release_binaries(&package_dir, &install_dir)?;
    let _ = fs::remove_dir_all(&work_dir);

    println!("已更新到 {}。", release.tag_name);
    if daemon_running {
        println!("提示：daemon 正在运行，执行 p2wlan down && p2wlan up 后会使用新版 daemon。");
    }
    Ok(())
}
