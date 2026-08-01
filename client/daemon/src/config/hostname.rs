// ============================================================
// hostname helper (simple, no external dep)
// ============================================================

mod hostname {
    use std::ffi::OsString;

    pub fn get() -> Result<OsString, std::io::Error> {
        #[cfg(target_os = "windows")]
        {
            // Use COMPUTERNAME env var on Windows
            std::env::var_os("COMPUTERNAME").ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "COMPUTERNAME not set")
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Use gethostname crate or nix
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "hostname not implemented",
            ))
        }
    }
}
