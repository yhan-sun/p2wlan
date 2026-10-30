impl Daemon {
    fn init_tun_with(
        &mut self,
        vip: &str,
        netmask: &str,
        mtu: u32,
    ) -> Result<Option<crate::os_request_capture::SystemTun>> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            #[cfg(target_env = "ohos")]
            return Err(DaemonError::Network(
                "HarmonyOS VPN engine requires its extension-owned TUN fd reason_code=ohos_vpn_tun_disabled"
                    .to_string(),
            ));

            #[cfg(not(target_env = "ohos"))]
            {
                warn!("TUN creation disabled via P2WLAN_DISABLE_TUN=1");
                return Ok(None);
            }
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
            let tun = crate::os_request_capture::SystemTun::from_raw_fd_with_mode(
                fd,
                &config,
                self.android_tun_mode,
            )
            .map_err(|e| DaemonError::Network(format!("failed to attach Android VPN TUN: {e}")))?;
            info!(
                "Android VPN TUN {} is attached at logical address {} MTU {} mode={:?}",
                tun.name(),
                tun.address(),
                tun.mtu(),
                self.android_tun_mode,
            );
            Ok(Some(tun))
        }

        #[cfg(target_env = "ohos")]
        {
            let fd = self.ohos_tun_fd.take().ok_or_else(|| {
                DaemonError::Network("HarmonyOS VPN Extension TUN fd was not supplied".to_string())
            })?;
            let tun = crate::os_request_capture::SystemTun::from_owned_fd(fd, &config).map_err(|e| {
                DaemonError::Network(format!("failed to attach HarmonyOS VPN TUN: {e}"))
            })?;
            info!(
                "HarmonyOS VPN TUN {} is attached at logical address {} MTU {}",
                tun.name(),
                tun.address(),
                tun.mtu(),
            );
            Ok(Some(tun))
        }

        #[cfg(all(not(target_os = "android"), not(target_env = "ohos")))]
        {
            let tun = crate::os_request_capture::SystemTun::create(&config).map_err(|e| {
                error!("[tun] startup failed: {e}");
                DaemonError::Network(format!("TUN startup failed: {e}"))
            })?;
            info!(
                "[tun] interface {} is up at {} MTU {}",
                tun.name(),
                tun.address(),
                tun.mtu()
            );
            Ok(Some(tun))
        }
    }
}
