//! Mock TUN device for testing without system privileges.
//!
//! Uses in-memory channels to simulate packet flow. The `MockTunController`
//! allows test code to inject packets and observe written packets.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::config::InterfaceConfig;
use crate::error::{Error, Result};
use crate::interface::VirtualInterface;

/// A mock TUN device that uses channels to simulate packet I/O.
///
/// Created in pairs: a `MockTunDevice` (the "interface" side) and a
/// `MockTunController` (the "test harness" side). The controller can
/// inject packets into the device and receive packets written by the device.
///
/// # Example
///
/// ```no_run
/// use p2pnet_tun::{MockTunDevice, VirtualInterface};
///
/// #[tokio::main]
/// async fn main() {
///     let (mut dev, mut ctrl) = MockTunDevice::new_pair("p2pnet0", 1420, "10.20.0.1");
///
///     // Inject a packet into the device
///     ctrl.inject(vec![0x45, 0x00]).await;
///
///     // The device reads it
///     let mut buf = [0u8; 65535];
///     let n = dev.read(&mut buf).await.unwrap();
///     assert_eq!(buf[0], 0x45);
/// }
/// ```
pub struct MockTunDevice {
    name: String,
    mtu: u32,
    address: String,
    is_up: bool,
    /// Packets that the device will read (injected by controller).
    read_rx: mpsc::Receiver<Vec<u8>>,
    /// Packets that the device writes (received by controller).
    write_tx: mpsc::Sender<Vec<u8>>,
}

/// The test harness side of a mock TUN device pair.
pub struct MockTunController {
    name: String,
    /// Inject packets into the device (device reads these).
    read_tx: mpsc::Sender<Vec<u8>>,
    /// Receive packets written by the device.
    write_rx: mpsc::Receiver<Vec<u8>>,
}

impl MockTunDevice {
    /// Create a mock device from a config.
    pub fn new(config: &InterfaceConfig) -> (Self, MockTunController) {
        Self::new_pair(&config.name, config.mtu, &config.address.to_string())
    }

    /// Create a mock device pair with the given parameters.
    pub fn new_pair(name: &str, mtu: u32, address: &str) -> (Self, MockTunController) {
        let (read_tx, read_rx) = mpsc::channel(256);
        let (write_tx, write_rx) = mpsc::channel(256);

        let device = Self {
            name: name.to_string(),
            mtu,
            address: address.to_string(),
            is_up: true,
            read_rx,
            write_tx,
        };

        let controller = MockTunController {
            name: name.to_string(),
            read_tx,
            write_rx,
        };

        (device, controller)
    }

    /// Create a mock device with default settings.
    pub fn new_default(name: &str) -> (Self, MockTunController) {
        Self::new_pair(name, 1420, "10.20.0.1")
    }
}

#[async_trait]
impl VirtualInterface for MockTunDevice {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.is_up {
            return Err(Error::DeviceClosed);
        }

        match self.read_rx.recv().await {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
            None => Err(Error::DeviceClosed),
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if !self.is_up {
            return Err(Error::DeviceClosed);
        }

        self.write_tx
            .send(buf.to_vec())
            .await
            .map_err(|_| Error::DeviceClosed)?;
        Ok(buf.len())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn address(&self) -> &str {
        &self.address
    }

    fn is_up(&self) -> bool {
        self.is_up
    }
}

impl MockTunDevice {
    /// Shut down the mock device.
    pub fn close(&mut self) {
        self.is_up = false;
    }
}

impl MockTunController {
    /// Inject a packet into the device (the device will read it).
    pub async fn inject(&self, data: Vec<u8>) -> Result<()> {
        self.read_tx
            .send(data)
            .await
            .map_err(|_| Error::DeviceClosed)
    }

    /// Try to receive a packet that was written by the device.
    pub async fn recv_written(&mut self) -> Result<Vec<u8>> {
        self.write_rx.recv().await.ok_or(Error::DeviceClosed)
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Ipv4Packet;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_mock_read_write() {
        let (mut dev, mut ctrl) = MockTunDevice::new_default("test0");

        // Build a test packet
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );

        // Inject into device
        ctrl.inject(packet.clone()).await.unwrap();

        // Device reads it
        let mut buf = [0u8; 65535];
        let n = dev.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &packet[..]);

        // Device writes it back
        dev.write(&buf[..n]).await.unwrap();

        // Controller receives the written packet
        let written = ctrl.recv_written().await.unwrap();
        assert_eq!(written, packet);
    }

    #[tokio::test]
    async fn test_mock_closed_device() {
        let (mut dev, _ctrl) = MockTunDevice::new_default("test0");
        dev.close();

        let mut buf = [0u8; 65535];
        assert!(dev.read(&mut buf).await.is_err());
        assert!(dev.write(&[0x45]).await.is_err());
    }

    #[tokio::test]
    async fn test_mock_interface_properties() {
        let (dev, _ctrl) = MockTunDevice::new_default("p2pnet0");

        assert_eq!(dev.name(), "p2pnet0");
        assert_eq!(dev.mtu(), 1420);
        assert_eq!(dev.address(), "10.20.0.1");
        assert!(dev.is_up());
    }
}
