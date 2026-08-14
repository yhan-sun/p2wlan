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

    resolve_stun_specs(specs, using_defaults, resolve_timeout).await
}

/// Resolve Direct-only STUN sources concurrently while preserving their
/// configured order.  Relay setup must not wait for a sequence of unrelated
/// DNS deadlines, but an explicitly configured malformed source remains a
/// configuration error rather than being silently discarded.
async fn resolve_stun_specs(
    specs: Vec<String>,
    using_defaults: bool,
    resolve_timeout: Duration,
) -> Result<Vec<SocketAddr>> {
    let outcomes = futures_util::future::join_all(specs.into_iter().map(|spec| async move {
        if is_stun_clear_value(&spec) {
            return Ok(Vec::new());
        }
        if let Ok(addr) = spec.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }

        let addrs = match tokio::time::timeout(resolve_timeout, lookup_host(&spec)).await {
            Ok(Ok(addrs)) => addrs,
            Err(_) if using_defaults => {
                warn!(
                    "Default STUN server {spec} resolution timed out after {} ms",
                    resolve_timeout.as_millis()
                );
                return Ok(Vec::new());
            }
            Err(_) => {
                // STUN is Direct-only best effort.  A resolver timeout must
                // never prevent the relay transport and encrypted session
                // from becoming usable, especially when the control plane is
                // reachable through a different network path.
                warn!(
                    "STUN server {spec} resolution timed out after {} ms; skipping this Direct candidate source",
                    resolve_timeout.as_millis()
                );
                return Ok(Vec::new());
            }
            Ok(Err(err)) if using_defaults => {
                warn!("Default STUN server {spec} could not be resolved: {err}");
                return Ok(Vec::new());
            }
            Ok(Err(err)) => {
                return Err(DaemonError::Config(format!(
                    "invalid or unresolved STUN server '{spec}': {err}"
                )));
            }
        };
        Ok(addrs.collect::<Vec<_>>())
    }))
    .await;

    let mut resolved = Vec::new();
    for outcome in outcomes {
        for addr in outcome? {
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
