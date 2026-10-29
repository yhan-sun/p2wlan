/// An empty primary configuration means the built-in defaults; an empty
/// observer configuration means disabled. Explicit off/none values stay off.
fn stun_discovery_configured(primary: &[String], observers: &[String]) -> bool {
    let enabled = |specs: &[String]| {
        specs.iter().any(|spec| {
            let spec = spec.trim();
            !spec.is_empty() && !is_stun_clear_value(spec)
        })
    };
    primary.is_empty() || enabled(primary) || enabled(observers)
}

#[allow(clippy::too_many_arguments)]
async fn recover_empty_stun_sources(
    udp: &UdpTransport,
    peers: &PeerManager,
    publication: &UdpTransportPublication,
    primary: &[String],
    observers: &[String],
    resolve_timeout: Duration,
    runtime: &Arc<RwLock<Vec<SocketAddr>>>,
) -> Option<Vec<SocketAddr>> {
    if !stun_discovery_configured(primary, observers) {
        return None;
    }
    let owner = UdpTransportOwner(udp.inbound_publication_owner());
    let generation = peers.current_network_generation_sync();
    if owner.0 == 0 {
        return None;
    }
    // Each hostname has the original resolver deadline. Both source lists
    // resolve concurrently inside this existing candidate worker, not a task
    // or queue that can survive its UDP owner.
    let (primary, observers) = tokio::join!(parse_stun_servers(primary, resolve_timeout), async {
        if observers.is_empty() {
            Ok(Vec::new())
        } else {
            parse_stun_servers(observers, resolve_timeout).await
        }
    },);
    let (Ok(mut resolved), Ok(observers)) = (primary, observers) else {
        debug!(
            event = "stun_source_recovery_deferred",
            reason = "resolution_failed"
        );
        return None;
    };
    for observer in observers {
        if !resolved.contains(&observer) {
            resolved.push(observer);
        }
    }
    if resolved.is_empty() {
        return None;
    }
    if let Err(reason) =
        commit_recovered_stun_sources(runtime, publication, peers, owner, generation, &resolved)
            .await
    {
        debug!(event = "stun_source_recovery_deferred", reason);
        return None;
    }
    info!(
        event = "stun_sources_recovered",
        count = resolved.len(),
        "Recovered initially unavailable STUN/observer sources"
    );
    Some(resolved)
}

/// Acquire the only awaited writer before the authoritative try-only gates.
/// DNS completion and writer contention cannot publish into a replacement
/// socket or generation, and no await follows the final identity check.
async fn commit_recovered_stun_sources(
    runtime: &Arc<RwLock<Vec<SocketAddr>>>,
    publication: &UdpTransportPublication,
    peers: &PeerManager,
    owner: UdpTransportOwner,
    generation: u64,
    resolved: &[SocketAddr],
) -> std::result::Result<(), &'static str> {
    let mut runtime = timeout(Duration::from_millis(100), runtime.write())
        .await
        .map_err(|_| "stun_sources_contended")?;
    let epoch_gate = peers.network_epoch_gate();
    let _epoch = epoch_gate
        .try_lock()
        .map_err(|_| "network_epoch_contended")?;
    let state = publication
        .inner
        .state
        .try_lock()
        .map_err(|_| "udp_publication_contended")?;
    if owner.0 == 0 || state.current_owner != Some(owner) {
        return Err("udp_transport_replaced");
    }
    if peers.current_network_generation_sync() != generation {
        return Err("network_generation_changed");
    }
    *runtime = resolved.to_vec();
    Ok(())
}

#[cfg(test)]
mod stun_recovery_tests {
    use super::*;
    include!("stun_recovery_tests.rs");
}
