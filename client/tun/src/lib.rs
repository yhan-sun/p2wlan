//! # p2pnet-tun
//!
//! Cross-platform virtual network interface (TUN/Wintun/utun) for P2PNet.
//!
//! Provides a unified async API for creating and managing virtual network
//! interfaces on Linux, Windows, and macOS.
//!
//! ## Quick Start
//!
//! ```no_run
//! use p2pnet_tun::{InterfaceConfig, TunDevice, VirtualInterface};
//!
//! #[tokio::main]
//! async fn main() -> p2pnet_tun::Result<()> {
//!     let config = InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 1420)?;
//!     let mut dev = TunDevice::create(&config)?;
//!
//!     println!("Interface: {} (MTU {})", dev.name(), dev.mtu());
//!
//!     let mut buf = [0u8; 65535];
//!     loop {
//!         let n = dev.read(&mut buf).await?;
//!         dev.write(&buf[..n]).await?; // echo back
//!     }
//! }
//! ```

pub mod config;
pub mod device;
pub mod error;
pub mod interface;
pub mod mock;
pub mod packet;
mod platform;

// Re-export primary types
pub use config::InterfaceConfig;
pub use device::TunDevice;
pub use error::{Error, Result};
pub use interface::VirtualInterface;
pub use mock::MockTunDevice;
pub use packet::{IpPacket, Ipv4Packet, Ipv6Packet, Protocol};
