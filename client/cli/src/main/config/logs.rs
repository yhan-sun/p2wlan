fn logs(lines: usize, follow: bool) -> Result<(), String> {
    let path = state_dir().join("p2wlan-daemon.log");
    if follow {
        let status = Command::new("tail")
            .arg("-n")
            .arg(lines.to_string())
            .arg("-f")
            .arg(&path)
            .status()
            .map_err(|error| format!("无法执行 tail：{error}"))?;
        if !status.success() {
            return Err(format!("tail 退出，状态：{status}"));
        }
        return Ok(());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取日志 {}：{error}", path.display()))?;
    let all = content.lines().collect::<Vec<_>>();
    for line in all.iter().skip(all.len().saturating_sub(lines)) {
        println!("{line}");
    }
    Ok(())
}
