use super::{is_stun_clear_value, RelayCandidateConfig, RelayCatalogEntry};

pub(crate) fn infer_default_relay_servers(control_server_url: &str) -> Vec<String> {
    // Relay endpoints are never inferred from the control host.  A relay must
    // arrive through an authenticated server catalog or an explicit local
    // setting.  Keep the environment override for controlled test/dev setups.
    if let Ok(configured) = std::env::var("P2WLAN_DEFAULT_RELAY") {
        return configured
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();
    }

    let _ = control_server_url;
    Vec::new()
}

pub(crate) fn effective_relay_allow_insecure_plaintext(
    control_server_url: &str,
    relay_catalog: &[RelayCatalogEntry],
    relay_servers: &[String],
    configured: bool,
) -> bool {
    if configured {
        return true;
    }

    if !control_server_uses_plaintext_http(control_server_url) {
        return false;
    }

    if !relay_catalog.is_empty() {
        return relay_catalog
            .iter()
            .any(|entry| relay_spec_is_plaintext(&entry.endpoint));
    }

    relay_servers
        .iter()
        .any(|server| relay_spec_is_plaintext(server))
}

pub(super) fn control_server_uses_plaintext_http(control_server_url: &str) -> bool {
    control_server_url
        .trim_start()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
}

pub(crate) fn relay_spec_is_plaintext(spec: &str) -> bool {
    let endpoint = spec
        .trim()
        .split_once('@')
        .map(|(_, endpoint)| endpoint)
        .unwrap_or_else(|| spec.trim())
        .trim();
    !endpoint.is_empty()
        && !endpoint
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tls://"))
}

pub(crate) fn relay_candidates_from_sources(
    relay_catalog: &[RelayCatalogEntry],
    relay_servers: &[String],
) -> Vec<RelayCandidateConfig> {
    if !relay_catalog.is_empty() {
        return relay_catalog
            .iter()
            .map(|entry| {
                RelayCandidateConfig::catalog(
                    entry.region.clone(),
                    entry.audience.clone(),
                    entry.endpoint.clone(),
                )
            })
            .collect();
    }

    relay_servers
        .iter()
        .cloned()
        .map(RelayCandidateConfig::legacy)
        .collect()
}

pub(crate) fn udp_observers_from_sources(
    relay_catalog: &[RelayCatalogEntry],
    configured_observers: &[String],
) -> Vec<String> {
    let configured = configured_observers
        .iter()
        .map(|observer| observer.trim())
        .filter(|observer| !observer.is_empty())
        .collect::<Vec<_>>();
    if configured
        .iter()
        .any(|observer| is_stun_clear_value(observer))
    {
        return configured.into_iter().map(ToString::to_string).collect();
    }

    let mut observers = Vec::new();
    for observer in configured {
        push_unique_udp_observer(&mut observers, observer);
    }
    for entry in relay_catalog {
        if let Some(observer) = entry.udp_observer_endpoint.as_deref() {
            push_unique_udp_observer(&mut observers, observer);
        }
        for observer in &entry.udp_observer_endpoints {
            push_unique_udp_observer(&mut observers, observer);
        }
    }
    observers
}

pub(super) fn push_unique_udp_observer(observers: &mut Vec<String>, observer: &str) {
    let observer = observer
        .trim()
        .strip_prefix("udp://")
        .unwrap_or_else(|| observer.trim())
        .trim();
    if observer.is_empty() {
        return;
    }
    if !observers.iter().any(|existing| existing == observer) {
        observers.push(observer.to_string());
    }
}
