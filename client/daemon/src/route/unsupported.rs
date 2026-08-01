#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl RouteManager {
    pub fn add_cidr_route(&self, _cidr: &str) -> crate::Result<()> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return Ok(());
        }
        Err(crate::DaemonError::Network(
            "routing configuration is not supported on this platform. Please use Linux or set P2WLAN_DISABLE_TUN=1."
                .to_string(),
        ))
    }

    pub fn cleanup(&self) {}
}
