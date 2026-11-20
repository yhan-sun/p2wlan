use clap::Subcommand;
use std::path::Path;

#[cfg(windows)]
#[path = "windows_service/manager.rs"]
mod windows;

#[derive(Debug, Subcommand)]
pub(crate) enum ServiceCommand {
    /// Start this device at boot (run as Administrator)
    Install {
        /// Copy the selected enrolled device identity into the administrator-only machine profile
        #[arg(long, required = true)]
        migrate_identity: bool,
    },
    /// Stop and remove the boot-time service, retaining the machine profile
    Uninstall,
    /// Show the Service Control Manager state
    Status {
        /// Use machine-readable output
        #[arg(long)]
        json: bool,
    },
}

pub(crate) fn run(config: &Path, command: ServiceCommand) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::run(config, command)
    }
    #[cfg(not(windows))]
    {
        let _ = (config, command);
        Err("service 命令仅支持 Windows".to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::Cli;
    use clap::Parser;

    #[test]
    fn identity_migration_requires_explicit_consent() {
        assert!(Cli::try_parse_from(["p2wlan", "service", "install"]).is_err());
        assert!(
            Cli::try_parse_from(["p2wlan", "service", "install", "--migrate-identity"]).is_ok()
        );
    }
}
