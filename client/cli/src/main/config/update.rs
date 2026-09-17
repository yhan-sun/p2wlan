fn github_release_endpoint(repo: &str, tag: Option<&str>) -> Result<String, String> {
    let repo = repo.trim();
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| "repo 必须形如 owner/name".to_string())?;
    if !is_github_slug(owner) || !is_github_slug(name) {
        return Err("repo 只能包含字母、数字、点、下划线和短横线".to_string());
    }
    if let Some(tag) = tag {
        let tag = tag.trim();
        if tag.is_empty() || !is_github_slug(tag) {
            return Err("version 只能包含字母、数字、点、下划线和短横线".to_string());
        }
        Ok(format!(
            "https://api.github.com/repos/{owner}/{name}/releases/tags/{tag}"
        ))
    } else {
        Ok(format!(
            "https://api.github.com/repos/{owner}/{name}/releases/latest"
        ))
    }
}

fn is_github_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn linux_release_arch() -> Result<&'static str, String> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x64"),
        ("linux", "aarch64") => Ok("arm64"),
        (os, arch) => Err(format!(
            "update 目前仅支持 Linux x64/arm64，当前是 {os}/{arch}"
        )),
    }
}

fn temp_update_dir() -> Result<PathBuf, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("系统时间异常：{error}"))?
        .as_millis();
    let path = env::temp_dir().join(format!("p2wlan-update-{}-{now}", std::process::id()));
    fs::create_dir(&path)
        .map_err(|error| format!("无法创建安全临时目录 {}：{error}", path.display()))?;
    Ok(path)
}

async fn download_to_file(url: &str, path: &Path) -> Result<(), String> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|error| format!("无法初始化下载请求：{error}"))?
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            format!("p2wlan-cli/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .map_err(|error| format!("下载更新包失败：{error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("下载更新包返回 HTTP {status}"));
    }
    if response
        .content_length()
        .is_some_and(|size| size > 100 * 1024 * 1024)
    {
        return Err("更新包超过 100 MiB，已拒绝下载".to_string());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("读取更新包失败：{error}"))?;
    fs::write(path, bytes.as_ref())
        .map_err(|error| format!("无法写入更新包 {}：{error}", path.display()))
}

fn extract_tar_gz(archive: &Path, directory: &Path) -> Result<(), String> {
    let listing = Command::new("tar")
        .arg("-tzf")
        .arg(archive)
        .output()
        .map_err(|error| format!("无法检查更新包：{error}"))?;
    if !listing.status.success() {
        return Err("更新包目录索引无效".to_string());
    }
    for raw in String::from_utf8_lossy(&listing.stdout).lines() {
        let path = raw.trim();
        if path.starts_with('/') || path.split('/').any(|part| part == "..") {
            return Err(format!("更新包包含不安全路径：{path}"));
        }
    }
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(directory)
        .arg("--no-same-owner")
        .arg("--no-same-permissions")
        .status()
        .map_err(|error| format!("无法执行 tar：{error}"))?;
    if !status.success() {
        return Err(format!("解压更新包失败（{status}）"));
    }
    Ok(())
}

fn verify_archive_checksum(archive: &Path, checksum_file: &Path) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let expected = fs::read_to_string(checksum_file)
        .map_err(|error| format!("无法读取更新包校验和：{error}"))?
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let digest = fields.next()?.trim();
            let name = fields.next().unwrap_or_default().trim_start_matches('*');
            if name.is_empty() || Path::new(name).file_name() == archive.file_name() {
                Some(digest.to_ascii_lowercase())
            } else {
                None
            }
        })
        .ok_or_else(|| "校验文件中没有更新包的 SHA-256".to_string())?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("更新包校验和格式无效".to_string());
    }
    let bytes = fs::read(archive).map_err(|error| format!("无法读取更新包：{error}"))?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected {
        return Err(format!(
            "更新包 SHA-256 不匹配：期望 {expected}，实际 {actual}"
        ));
    }
    Ok(())
}

fn install_release_binaries(package_dir: &Path, install_dir: &Path) -> Result<(), String> {
    let cli = package_dir.join("p2wlan");
    let daemon = package_dir.join("p2wlan-daemon");
    if !cli.is_file() || !daemon.is_file() {
        return Err(format!(
            "更新包缺少 p2wlan 或 p2wlan-daemon：{}",
            package_dir.display()
        ));
    }
    if !is_root() {
        println!(
            "需要管理员权限安装到 {}，正在请求 sudo...",
            install_dir.display()
        );
    }
    let install_args = vec![OsString::from("-d"), install_dir.as_os_str().to_os_string()];
    run_install_command(install_args)?;
    run_install_command(vec![
        OsString::from("-m"),
        OsString::from("0755"),
        cli.as_os_str().to_os_string(),
        install_dir.join("p2wlan").as_os_str().to_os_string(),
    ])?;
    run_install_command(vec![
        OsString::from("-m"),
        OsString::from("0755"),
        daemon.as_os_str().to_os_string(),
        install_dir.join("p2wlan-daemon").as_os_str().to_os_string(),
    ])?;
    Ok(())
}

fn run_install_command(args: Vec<OsString>) -> Result<(), String> {
    let status = Command::new("install")
        .args(&args)
        .status()
        .map_err(|error| format!("无法执行 install：{error}"))?;
    if status.success() {
        return Ok(());
    }
    if is_root() {
        return Err(format!("安装文件失败（{status}）"));
    }
    // Try the user's own directory first.  Only a genuinely unwritable
    // destination falls back to sudo; this keeps --install-dir "$HOME/.local/bin"
    // usable without an unnecessary privilege prompt.
    let elevated = Command::new("sudo")
        .arg("install")
        .args(args)
        .status()
        .map_err(|error| format!("无法执行 install：{error}"))?;
    if !elevated.success() {
        return Err(format!("安装文件失败（{elevated}）"));
    }
    Ok(())
}
