impl Daemon {
    fn init_tun_with(&mut self, vip: &str, netmask: &str, mtu: u32) -> Result<Option<TunDevice>> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            warn!("TUN creation disabled via P2WLAN_DISABLE_TUN=1");
            return Ok(None);
        }

        let config = InterfaceConfig::new(&self.config.network.interface, vip, netmask, mtu)
            .map_err(|e| DaemonError::Network(format!("invalid TUN config: {e}")))?;

        #[cfg(target_os = "android")]
        {
            let fd = self.android_tun_fd.take().ok_or_else(|| {
                DaemonError::Network(
                    "Android VPN TUN fd was not supplied by VpnService".to_string(),
                )
            })?;
            let tun = TunDevice::from_raw_fd(fd, &config)
                .map_err(|e| DaemonError::Network(format!("failed to attach Android VPN TUN: {e}")))?;
            info!(
                "Android VPN TUN {} is attached at logical address {} MTU {}",
                tun.name(),
                tun.address(),
                tun.mtu()
            );
            return Ok(Some(tun));
        }

        #[cfg(not(target_os = "android"))]
        {
            let tun = TunDevice::create(&config).map_err(|e| {
                DaemonError::Network(format!("failed to create TUN interface: {e}"))
            })?;
            info!(
                "TUN interface {} is up at {} MTU {}",
                tun.name(),
                tun.address(),
                tun.mtu()
            );
            return Ok(Some(tun));
        }
    }

}
