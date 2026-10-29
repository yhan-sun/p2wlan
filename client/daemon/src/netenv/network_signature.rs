//! Stable physical network observations. These are inputs to the existing
//! two-sample lifecycle monitors, never an independent connection owner.

use std::net::IpAddr;

fn physical_interface(name: &str, excluded: &[String]) -> bool {
    let name = name.trim().to_ascii_lowercase();
    !name.is_empty()
        && name != "lo"
        && name != "lo0"
        // PPP can be a mobile-broadband/dial-up upstream. Observing it here
        // does not change the separate physical socket-binding policy.
        && (!super::is_virtual_interface_name(&name) || name.starts_with("ppp"))
        && ![
            "p2wlan", "p2pnet", "p2r", "wintun", "docker", "awdl", "llw",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        // A routed bridge can be the actual upstream (OpenWrt br-lan or
        // Hyper-V vEthernet). Only Unix veth devices use this container
        // naming convention; never apply it to Windows friendly aliases.
        && (!cfg!(unix) || !name.starts_with("veth") || name.starts_with("vethernet"))
        && !excluded
            .iter()
            .any(|excluded| excluded.trim().eq_ignore_ascii_case(&name))
}

fn address_entry(identity: &str, address: IpAddr, prefix: u8) -> Option<String> {
    if address.is_loopback() || address.is_unspecified() || address.is_multicast() {
        return None;
    }
    if (address.is_ipv4() && prefix > 32) || prefix > 128 {
        return None;
    }
    Some(format!("address:{identity}:{address}/{prefix}"))
}

#[cfg(unix)]
pub(super) fn append_unix_addresses(
    signature: &mut Vec<String>,
    default_interface: Option<&str>,
    physical_interface: Option<&str>,
    public_interfaces: &[String],
    excluded: &[String],
) {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return;
    };
    let relevant = default_interface
        .into_iter()
        .chain(physical_interface)
        .chain(public_interfaces.iter().map(String::as_str))
        .collect::<Vec<_>>();
    for interface in interfaces.into_iter().take(4096) {
        if !interface.is_oper_up() {
            continue;
        }
        let (address, prefix) = match interface.addr {
            if_addrs::IfAddr::V4(value) => (IpAddr::V4(value.ip), value.prefixlen),
            if_addrs::IfAddr::V6(value) => (IpAddr::V6(value.ip), value.prefixlen),
        };
        append_relevant_address(
            signature,
            &relevant,
            excluded,
            &interface.name,
            address,
            prefix,
        );
    }
}

#[cfg(any(unix, test))]
pub(super) fn append_ipv6_default(
    signature: &mut Vec<String>,
    path: Option<(String, Option<String>)>,
    excluded: &[String],
) -> Option<String> {
    let (interface, gateway) = path?;
    if !physical_interface(&interface, excluded) {
        return None;
    }
    signature.push(format!(
        "default6:{interface}:{}",
        gateway.unwrap_or_default()
    ));
    Some(interface)
}

#[cfg(any(unix, test))]
fn append_relevant_address(
    signature: &mut Vec<String>,
    relevant: &[&str],
    excluded: &[String],
    name: &str,
    address: IpAddr,
    prefix: u8,
) {
    if !relevant.contains(&name) || !physical_interface(name, excluded) {
        return;
    }
    if let Some(entry) = address_entry(name, address, prefix) {
        signature.push(entry);
    }
}

#[cfg(any(windows, test))]
#[derive(Clone)]
pub(super) struct WindowsAdapter {
    pub name: String,
    pub luid: u64,
    pub up: bool,
    pub tunnel: bool,
    pub network_id: String,
    pub ipv4_metric: u32,
    pub ipv6_metric: u32,
    pub addresses: Vec<(IpAddr, u8)>,
}

#[cfg(any(windows, test))]
#[derive(Clone)]
pub(super) struct WindowsDefaultRoute {
    pub luid: u64,
    pub index: u32,
    pub next_hop: IpAddr,
    pub scope: u32,
    pub metric: u32,
}

#[cfg(any(windows, test))]
pub(super) fn windows_signature(
    adapters: &[WindowsAdapter],
    routes: &[WindowsDefaultRoute],
    excluded: &[String],
) -> Vec<String> {
    let mut signature = Vec::new();
    for adapter in adapters.iter().filter(|adapter| {
        adapter.up && !adapter.tunnel && physical_interface(&adapter.name, excluded)
    }) {
        let mut relevant = false;
        for route in routes.iter().filter(|route| route.luid == adapter.luid) {
            relevant = true;
            let interface_metric = if route.next_hop.is_ipv4() {
                adapter.ipv4_metric
            } else {
                adapter.ipv6_metric
            };
            signature.push(format!(
                "default:{}:{}:{}%{}:{}:{}",
                route.luid,
                route.index,
                route.next_hop,
                route.scope,
                route.metric,
                interface_metric,
            ));
        }
        if relevant {
            signature.push(format!("network:{}:{}", adapter.luid, adapter.network_id));
            let identity = adapter.luid.to_string();
            for (address, prefix) in &adapter.addresses {
                if let Some(entry) = address_entry(&identity, *address, *prefix) {
                    signature.push(entry);
                }
            }
        }
    }
    signature.sort();
    signature.dedup();
    signature
}

#[cfg(test)]
mod tests;
