#[cfg(target_os = "windows")]
fn windows_get_route_aliases(destination_prefix: &str) -> crate::Result<Vec<String>> {
    let output = windows_powershell_output(&format!(
        "$ErrorActionPreference = 'SilentlyContinue'; Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{}' -ErrorAction SilentlyContinue 2>$null | ForEach-Object {{ $_.InterfaceAlias }}; exit 0",
        ps_quote(destination_prefix)
    ), WINDOWS_ROUTE_QUERY_TIMEOUT)?;

    if !output.status.success() {
        return Err(crate::DaemonError::Network(format!(
            "Get-NetRoute failed for {destination_prefix}: {}",
            powershell_failure_detail(&output)
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

#[cfg(target_os = "windows")]
fn windows_remove_stale_managed_routes(
    destination_prefix: &str,
    current_interface: &str,
    aliases: &[String],
) -> bool {
    let stale_aliases: Vec<&str> = aliases
        .iter()
        .map(String::as_str)
        .filter(|alias| !windows_interface_alias_eq(alias, current_interface))
        .filter(|alias| windows_is_managed_interface_alias(alias))
        .collect();

    for alias in &stale_aliases {
        info!(
            "Removing stale Windows route for {destination_prefix} via {alias} before using {current_interface}"
        );
        let output = windows_powershell_output(&format!(
            "$ErrorActionPreference = 'SilentlyContinue'; Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{}' -InterfaceAlias '{}' -ErrorAction SilentlyContinue 2>$null | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; exit 0",
            ps_quote(destination_prefix),
            ps_quote(alias)
        ), WINDOWS_ROUTE_QUERY_TIMEOUT);

        match output {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                warn!(
                    "Could not remove stale Windows route for {destination_prefix} via {alias}: {}",
                    powershell_failure_detail(&output)
                );
            }
            Err(err) => {
                warn!(
                    "Could not run stale Windows route cleanup for {destination_prefix} via {alias}: {err}"
                );
            }
        }
    }

    !stale_aliases.is_empty()
}

#[cfg(any(target_os = "windows", test))]
fn windows_is_managed_interface_alias(alias: &str) -> bool {
    let alias = alias.trim().to_ascii_lowercase();
    alias == "p2wlan" || alias.starts_with("p2wlan-") || alias.starts_with("p2pnet")
}

#[cfg(target_os = "windows")]
fn windows_route_already_exists(output: &std::process::Output) -> bool {
    windows_route_already_exists_message(
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )
}

#[cfg(any(target_os = "windows", test))]
fn windows_route_already_exists_message(stdout: &str, stderr: &str) -> bool {
    let text = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    text.contains("already exists")
        || text.contains("object already exists")
        || text.contains("对象已存在")
        || text.contains("物件已存在")
        || text.contains("路由已存在")
        || (text.contains("msft_netroute") && text.contains("system error 87"))
}

#[cfg(any(target_os = "windows", test))]
fn windows_netsh_route_output_has_interface(
    stdout: &str,
    destination_prefix: &str,
    interface: &str,
) -> bool {
    let interface = interface.to_ascii_lowercase();
    stdout.lines().any(|line| {
        line.contains(destination_prefix) && line.to_ascii_lowercase().contains(&interface)
    })
}

#[cfg(target_os = "windows")]
fn windows_interface_alias_eq(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

#[cfg(target_os = "windows")]
fn windows_ensure_icmp_echo_firewall_rule(destination_prefix: &str) {
    const RULE_NAME: &str = "p2wlan Overlay ICMPv4 Echo Request";
    let output = windows_powershell_output(&format!(
        "$ErrorActionPreference = 'Stop'; $name = '{}'; $cidr = '{}'; $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $rule) {{ New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -LocalAddress $cidr -RemoteAddress $cidr -Profile Any | Out-Null }} else {{ Enable-NetFirewallRule -DisplayName $name | Out-Null }}",
        ps_quote(RULE_NAME),
        ps_quote(destination_prefix)
    ), std::time::Duration::from_secs(8));

    match output {
        Ok(output) if output.status.success() => {
            info!("Windows firewall rule ensured for ICMPv4 echo on overlay {destination_prefix}");
        }
        Ok(output) => {
            warn!(
                "Could not ensure Windows firewall ICMPv4 echo rule for {destination_prefix}: {}",
                powershell_failure_detail(&output)
            );
        }
        Err(err) => {
            warn!(
                "Could not run Windows firewall ICMPv4 echo rule command for {destination_prefix}: {err}"
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_netsh_route_exists_on_interface(destination_prefix: &str, interface: &str) -> bool {
    let output = windows_command_output_with_timeout(
        {
            let mut command = windows_hidden_command("netsh.exe");
            command
                .args(["interface", "ipv4", "show", "route"])
                .arg("level=verbose")
                .arg("store=active");
            command
        },
        std::time::Duration::from_secs(8),
    );

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            windows_netsh_route_output_has_interface(&stdout, destination_prefix, interface)
        }
        Ok(output) => {
            warn!(
                "Could not query Windows route table with netsh for {destination_prefix} via {interface}: {}",
                command_failure_detail(&output)
            );
            false
        }
        Err(err) => {
            warn!(
                "Could not run netsh route query for {destination_prefix} via {interface}: {err}"
            );
            false
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_netsh_add_route(
    destination_prefix: &str,
    interface: &str,
    network: Ipv4Addr,
    mask: Ipv4Addr,
    manager: &RouteManager,
) -> crate::Result<()> {
    let output = windows_command_output_with_timeout(
        {
            let mut command = windows_hidden_command("netsh.exe");
            command
                .args(["interface", "ipv4", "add", "route"])
                .arg(format!("prefix={destination_prefix}"))
                .arg(format!("interface={interface}"))
                .arg("nexthop=0.0.0.0")
                .arg("store=active");
            command
        },
        std::time::Duration::from_secs(8),
    )
    .map_err(|error| {
        crate::DaemonError::Network(format!("failed to run netsh route add: {error}"))
    })?;

    if output.status.success() {
        if let Ok(mut added) = manager.routes_added.lock() {
            added.push((network, mask));
        }
        info!("Windows route for {destination_prefix} via {interface} added using netsh");
        return Ok(());
    }

    if windows_route_already_exists(&output) {
        let existing_after = windows_get_route_aliases(destination_prefix).unwrap_or_default();
        if existing_after.is_empty()
            || existing_after
                .iter()
                .any(|alias| windows_interface_alias_eq(alias, interface))
        {
            if let Ok(mut added) = manager.routes_added.lock() {
                added.push((network, mask));
            }
            info!(
                "Windows route for {destination_prefix} via {interface} already exists after netsh fallback"
            );
            return Ok(());
        }
        return Err(crate::DaemonError::Network(format!(
            "routing conflict: route to {destination_prefix} already exists on another interface: {}",
            existing_after.join(", ")
        )));
    }

    if windows_netsh_route_exists_on_interface(destination_prefix, interface) {
        if let Ok(mut added) = manager.routes_added.lock() {
            added.push((network, mask));
        }
        info!(
            "Windows route for {destination_prefix} via {interface} exists after netsh fallback failure"
        );
        return Ok(());
    }

    Err(crate::DaemonError::Network(format!(
        "netsh route add failed for {destination_prefix} via {interface}: {}",
        command_failure_detail(&output)
    )))
}

#[cfg(target_os = "windows")]
fn powershell_failure_detail(output: &std::process::Output) -> String {
    command_failure_detail(output)
}

#[cfg(target_os = "windows")]
fn command_failure_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match (stderr.is_empty(), stdout.is_empty(), output.status.code()) {
        (false, false, code) => format!(
            "exit={}; stderr={}; stdout={}",
            code.map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            stderr,
            stdout
        ),
        (false, true, code) => format!(
            "exit={}; stderr={}",
            code.map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            stderr
        ),
        (true, false, code) => format!(
            "exit={}; stdout={}",
            code.map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            stdout
        ),
        (true, true, code) => format!(
            "exit={}; no PowerShell output",
            code.map_or_else(|| "unknown".to_string(), |code| code.to_string())
        ),
    }
}

#[cfg(target_os = "windows")]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn windows_powershell_command(script: &str) -> Command {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut command = Command::new("powershell.exe");
    command.creation_flags(CREATE_NO_WINDOW).args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]);
    command
}

#[cfg(target_os = "windows")]
fn windows_powershell_output(
    script: &str,
    timeout: std::time::Duration,
) -> crate::Result<std::process::Output> {
    windows_command_output_with_timeout(windows_powershell_command(script), timeout).map_err(
        |error| {
            crate::DaemonError::Network(format!(
                "PowerShell command timed out or failed after {:?}: {error}",
                timeout
            ))
        },
    )
}

#[cfg(target_os = "windows")]
fn windows_hidden_command(program: &str) -> Command {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

#[cfg(target_os = "windows")]
fn windows_command_output_with_timeout(
    mut command: Command,
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    use std::io;
    use std::process::Stdio;

    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("command exceeded {:?}", timeout),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
