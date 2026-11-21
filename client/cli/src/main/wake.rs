#[derive(Subcommand)]
enum WakeCommand {
    /// Send a Wake-on-LAN magic packet without connecting to Control
    Send {
        /// Target's Ethernet MAC address
        #[arg(long)]
        mac: String,
        /// Limit directed broadcasts to this local LAN interface
        #[arg(long)]
        interface: Option<String>,
    },
    /// Show Wake-on-LAN daemon status
    Status,
    /// Enable or disable this device as a wake proxy
    Proxy {
        #[command(subcommand)]
        action: WakeProxyAction,
    },
    /// Manage manually configured wake targets
    Target {
        #[command(subcommand)]
        command: WakeTargetCommand,
    },
}

impl std::fmt::Debug for WakeCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Send { .. } => "Send",
            Self::Status => "Status",
            Self::Proxy { .. } => "Proxy",
            Self::Target { .. } => "Target",
        })
    }
}

async fn wake_command(config_path: &Path, command: WakeCommand) -> Result<(), String> {
    match command {
        WakeCommand::Send { mac, interface } => {
            let mac = mac
                .parse::<p2pnet_netbind::wake::MacAddress>()
                .map_err(|error| error.to_string())?;
            p2pnet_netbind::wake::send_magic_packet(mac, interface.as_deref())
                .await
                .map_err(|error| error.to_string())?;
            println!("已向局域网提交唤醒包，等待目标机器开机。");
            Ok(())
        }
        WakeCommand::Status => wake_status(config_path).await,
        WakeCommand::Proxy { action } => wake_proxy(config_path, action),
        WakeCommand::Target { command } => wake_targets(config_path, command).await,
    }
}

#[cfg(test)]
mod wake_send_tests {
    use super::{Cli, Commands, Parser, WakeCommand};

    #[test]
    fn cli_parses_local_wake_send_and_redacts_debug() {
        let mac = "02:11:22:33:44:50";
        let cli = Cli::try_parse_from([
            "p2wlan",
            "wake",
            "send",
            "--mac",
            mac,
            "--interface",
            "br-lan",
        ])
        .unwrap();
        assert!(!format!("{:?}", cli.command).contains(mac));
        assert!(matches!(
            cli.command,
            Commands::Wake {
                command: WakeCommand::Send { mac: selected_mac, interface: Some(interface) },
            } if selected_mac == mac && interface == "br-lan"
        ));
    }
}
