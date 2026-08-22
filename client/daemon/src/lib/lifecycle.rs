// ============================================================
// Drop, helpers, and Tests
// ============================================================

impl Drop for Daemon {
    fn drop(&mut self) {
        info!("Daemon cleanup: removing routes...");
        self.route_manager.cleanup();
        #[cfg(target_os = "android")]
        if let Some(fd) = self.android_tun_fd.take() {
            // Before registration succeeds, init_tun_with has not taken the
            // raw fd yet. RawFd itself has no Drop implementation, so close
            // that ownership explicitly on early shutdown/error paths. Once
            // attached, android_tun_fd is None and TunDevice owns it instead.
            unsafe {
                drop(<std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd));
            }
        }
    }
}

fn cidr_to_netmask(cidr: &str) -> Option<String> {
    let (_, prefix_str) = cidr.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask_u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let mask = std::net::Ipv4Addr::from(mask_u32);
    Some(mask.to_string())
}

fn is_ip_in_cidr(ip_str: &str, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(net_ip) = net_str.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }

    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(net_ip);

    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };

    (ip_u32 & mask) == (net_u32 & mask)
}
