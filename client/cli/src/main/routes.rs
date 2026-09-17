#[derive(Subcommand, Debug)]
enum RouteCommand {
    /// Read the live overlay route without changing the system routing table
    Verify {
        /// Print the daemon response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Repair a missing or conflicting overlay route in place
    Repair {
        /// Print the daemon response as JSON
        #[arg(long)]
        json: bool,
    },
}

async fn route_command(config_path: &Path, command: RouteCommand) -> Result<(), String> {
    let config = load_config(config_path)?;
    let state = state_dir_for_config(config_path);
    match command {
        RouteCommand::Verify { json } => {
            let url = diagnostics_endpoint(&config, "/routes/verify");
            let (status, body) = diagnostics_request(&url, &state, reqwest::Method::POST).await?;
            let value = parse_json_response(&body, "路由校验")?;
            if json {
                print_json(&value)?;
            } else {
                print_route_report(&value, false);
            }
            if !status.is_success() {
                return Err(format!("路由校验返回 HTTP {status}"));
            }
            if value.get("healthy").and_then(Value::as_bool) != Some(true) {
                return Err("路由校验未通过；可运行 p2wlan route repair 尝试修复".to_string());
            }
            Ok(())
        }
        RouteCommand::Repair { json } => {
            let url = diagnostics_endpoint(&config, "/routes/repair");
            let (status, body) = diagnostics_request(&url, &state, reqwest::Method::POST).await?;
            let value = parse_json_response(&body, "路由修复")?;
            if json {
                print_json(&value)?;
            } else {
                print_route_report(&value, true);
            }
            if !status.is_success() {
                return Err(format!(
                    "路由修复未完成（HTTP {status}）：{}",
                    value
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                ));
            }
            Ok(())
        }
    }
}

fn diagnostics_endpoint(config: &Config, path: &str) -> String {
    format!(
        "http://{}{}",
        normalized_diagnostics_bind(&config.diagnostics.bind),
        path
    )
}

fn parse_json_response(body: &str, operation: &str) -> Result<Value, String> {
    serde_json::from_str(body).map_err(|error| {
        let preview = body.trim().chars().take(160).collect::<String>();
        format!("{operation}响应不是有效 JSON：{error}（{preview}）")
    })
}

fn print_json(value: &Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn print_route_report(value: &Value, repair: bool) {
    if repair {
        let cidr = value.get("cidr").and_then(Value::as_str).unwrap_or("?");
        let before = value.get("before").and_then(Value::as_str).unwrap_or("?");
        let after = value.get("after").and_then(Value::as_str).unwrap_or("?");
        let changed = value
            .get("changed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let reason = value.get("reason").and_then(Value::as_str).unwrap_or("?");
        println!(
            "路由修复：{cidr} {before} -> {after}（{}，原因：{reason}）",
            if changed { "已变更" } else { "无需变更" }
        );
        return;
    }

    let healthy = value
        .get("healthy")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let interface = value
        .get("interface")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let mtu = value.get("mtu").and_then(Value::as_u64).unwrap_or(0);
    println!(
        "路由校验：{}（interface={interface}, mtu={mtu}）",
        if healthy { "正常" } else { "异常" }
    );
    if let Some(entries) = value.get("entries").and_then(Value::as_array) {
        for entry in entries {
            println!(
                "  {}: {} -> {}{}",
                entry.get("cidr").and_then(Value::as_str).unwrap_or("?"),
                entry.get("state").and_then(Value::as_str).unwrap_or("?"),
                entry
                    .get("actual_interface")
                    .and_then(Value::as_str)
                    .unwrap_or("(none)"),
                if entry.get("owned").and_then(Value::as_bool) == Some(true) {
                    " [owned]"
                } else {
                    ""
                }
            );
        }
    }
}
