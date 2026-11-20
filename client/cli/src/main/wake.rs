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
}

impl std::fmt::Debug for WakeCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Send { .. } => "Send",
        })
    }
}

async fn wake_command(_config_path: &Path, command: WakeCommand) -> Result<(), String> {
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
    }
}
