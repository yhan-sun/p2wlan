async fn parse_stun_servers(
    values: &[String],
    resolve_timeout: Duration,
) -> Result<Vec<SocketAddr>> {
    let using_defaults = values.is_empty();
    let specs: Vec<String> = if using_defaults {
        DEFAULT_STUN_SERVERS
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        values
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect()
    };

    if specs
        .iter()
        .all(|value| is_stun_clear_value(value.as_str()))
    {
        return Ok(Vec::new());
    }

    let mut resolved = Vec::new();
    for spec in specs {
        if is_stun_clear_value(&spec) {
            continue;
        }
        if let Ok(addr) = spec.parse::<SocketAddr>() {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
            continue;
        }

        let addrs = match tokio::time::timeout(resolve_timeout, lookup_host(&spec)).await {
            Ok(Ok(addrs)) => addrs,
            Err(_) if using_defaults => {
                warn!(
                    "Default STUN server {spec} resolution timed out after {} ms",
                    resolve_timeout.as_millis()
                );
                continue;
            }
            Err(_) => {
                return Err(DaemonError::Config(format!(
                    "STUN server '{spec}' resolution timed out after {} ms",
                    resolve_timeout.as_millis()
                )));
            }
            Ok(Err(err)) if using_defaults => {
                warn!("Default STUN server {spec} could not be resolved: {err}");
                continue;
            }
            Ok(Err(err)) => {
                return Err(DaemonError::Config(format!(
                    "invalid or unresolved STUN server '{spec}': {err}"
                )));
            }
        };
        for addr in addrs {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
        }
    }

    Ok(resolved)
}

fn is_stun_clear_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "none" | "off" | "false" | "clear" | "unset" | "disable" | "disabled"
    )
}
