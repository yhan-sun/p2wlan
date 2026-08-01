impl Daemon {
    fn init_tun_with(&self, vip: &str, netmask: &str, mtu: u32) -> Result<Option<TunDevice>> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            warn!("TUN creation disabled via P2WLAN_DISABLE_TUN=1");
            return Ok(None);
        }

        let config = InterfaceConfig::new(&self.config.network.interface, vip, netmask, mtu)
            .map_err(|e| DaemonError::Network(format!("invalid TUN config: {e}")))?;

        let tun = TunDevice::create(&config)
            .map_err(|e| DaemonError::Network(format!("failed to create TUN interface: {e}")))?;
        info!(
            "TUN interface {} is up at {} MTU {}",
            tun.name(),
            tun.address(),
            tun.mtu()
        );

        Ok(Some(tun))
    }

}
