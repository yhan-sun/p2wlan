fn log_follow_command(path: &std::path::Path, lines: usize) -> Command {
    let mut command = Command::new("tail");
    command
        .arg("-n")
        .arg(lines.to_string())
        .arg("-F")
        .arg(path);
    command
}

fn logs(lines: usize, follow: bool) -> Result<(), String> {
    let path = state_dir().join("p2wlan-daemon.log");
    if follow {
        let status = log_follow_command(&path, lines)
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

#[cfg(test)]
mod log_follow_tests {
    use super::*;

    #[test]
    fn following_logs_reopens_the_file_after_rotation() {
        let path = std::path::Path::new("state with spaces/p2wlan-daemon.log");
        let command = log_follow_command(path, 120);
        assert_eq!(command.get_program(), "tail");
        let arguments = command.get_args().collect::<Vec<_>>();
        assert_eq!(arguments, ["-n", "120", "-F", "state with spaces/p2wlan-daemon.log"]);
    }
}
