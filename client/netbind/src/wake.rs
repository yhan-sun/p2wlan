//! Local IPv4 Wake-on-LAN. The socket always uses an eligible LAN interface
//! and this module only sends the fixed magic-packet payload.

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    windows
))]
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::time::Duration;

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[path = "wake/linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "wake/macos.rs"]
mod platform;
#[cfg(windows)]
#[path = "wake/windows.rs"]
mod platform;

const WAKE_PORTS: [u16; 2] = [9, 7];
const BURST_COUNT: usize = 3;
const BURST_INTERVAL: Duration = Duration::from_millis(100);
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    windows
))]
type LinkMetadata = HashMap<u32, (MacAddress, bool)>;

/// A validated, six-byte unicast address. Debug formatting redacts the value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    fn from_bytes(bytes: [u8; 6]) -> Result<Self, InvalidMacAddress> {
        if bytes == [0; 6] || bytes[0] & 1 != 0 {
            return Err(InvalidMacAddress);
        }
        Ok(Self(bytes))
    }
}

impl FromStr for MacAddress {
    type Err = InvalidMacAddress;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim().as_bytes();
        let regular = value.len() == 17 && matches!(value[2], b':' | b'-');
        if !regular && value.len() != 12 {
            return Err(InvalidMacAddress);
        }
        let stride = if regular { 3 } else { 2 };
        let mut address = [0; 6];
        for (i, byte) in address.iter_mut().enumerate() {
            let start = i * stride;
            if regular && i > 0 && value[start - 1] != value[2] {
                return Err(InvalidMacAddress);
            }
            let high = char::from(value[start])
                .to_digit(16)
                .ok_or(InvalidMacAddress)?;
            let low = char::from(value[start + 1])
                .to_digit(16)
                .ok_or(InvalidMacAddress)?;
            *byte = ((high << 4) | low) as u8;
        }
        Self::from_bytes(address)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, last] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{last:02x}")
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MacAddress([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMacAddress;

impl fmt::Display for InvalidMacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a six-byte unicast MAC address")
    }
}

impl std::error::Error for InvalidMacAddress {}

/// One IPv4 address and directed broadcast on a broadcast-capable LAN link.
#[derive(Clone, PartialEq, Eq)]
pub struct LanInterface {
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub mac: MacAddress,
    pub wired: bool,
}

/// Enumerate active LAN IPv4 interfaces. Results may include an interface
/// more than once when it is configured with addresses in different subnets.
pub fn list_lan_interfaces() -> io::Result<Vec<LanInterface>> {
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        windows
    ))]
    {
        let mut interfaces = Vec::new();
        let metadata = platform::link_metadata()?;
        for interface in if_addrs::get_if_addrs()? {
            if interface.is_loopback()
                || interface.is_p2p()
                || !interface.is_oper_up()
                || excluded_interface(&interface.name)
            {
                continue;
            }
            let if_addrs::IfAddr::V4(address) = interface.addr else {
                continue;
            };
            let Some(broadcast) = directed_broadcast(address.ip, address.netmask) else {
                continue;
            };
            let Some(&(mac, wired)) = interface.index.and_then(|index| metadata.get(&index)) else {
                continue;
            };
            interfaces.push(LanInterface {
                name: interface.name,
                ipv4: address.ip,
                netmask: address.netmask,
                broadcast,
                mac,
                wired,
            });
        }
        interfaces
            .sort_unstable_by(|a, b| (a.name.as_str(), a.ipv4).cmp(&(b.name.as_str(), b.ipv4)));
        interfaces.dedup();
        Ok(interfaces)
    }
    #[cfg(not(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        windows
    )))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    windows,
    test
))]
fn directed_broadcast(ip: Ipv4Addr, mask: Ipv4Addr) -> Option<Ipv4Addr> {
    let host_bits = !u32::from(mask);
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || host_bits <= 1
        || host_bits == u32::MAX
        || host_bits & (host_bits + 1) != 0
    {
        return None;
    }
    let host = u32::from(ip) & host_bits;
    if host == 0 || host == host_bits {
        return None;
    }
    let broadcast = u32::from(ip) | host_bits;
    (broadcast != u32::MAX).then(|| broadcast.into())
}

/// Stable failure classes keep adapter details and socket addresses private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeSendError {
    NoLanInterface,
    SendFailed,
    UnsupportedPlatform,
}

impl WakeSendError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoLanInterface => "no_lan_interface",
            Self::SendFailed => "send_failed",
            Self::UnsupportedPlatform => "unsupported_platform",
        }
    }
}

impl fmt::Display for WakeSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for WakeSendError {}

/// Send a standard magic packet to each selected LAN broadcast destination.
/// Success means at least one datagram was accepted by the local kernel.
pub async fn send_magic_packet(
    mac: MacAddress,
    interface: Option<&str>,
) -> Result<(), WakeSendError> {
    send_magic_packet_excluding(mac, interface, "").await
}

/// Send a magic packet, skipping the caller's configured overlay interface.
pub async fn send_magic_packet_excluding(
    mac: MacAddress,
    interface: Option<&str>,
    excluded: &str,
) -> Result<(), WakeSendError> {
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        windows
    ))]
    if interface.is_some_and(|name| excluded_interface(name.trim())) {
        return Err(WakeSendError::NoLanInterface);
    }
    let interfaces = list_lan_interfaces().map_err(|err| {
        if err.kind() == io::ErrorKind::Unsupported {
            WakeSendError::UnsupportedPlatform
        } else {
            WakeSendError::SendFailed
        }
    })?;
    send_to_lans(mac, distinct_broadcasts(&interfaces, interface, excluded)).await
}

fn distinct_broadcasts<'a>(
    interfaces: &'a [LanInterface],
    requested: Option<&'a str>,
    excluded: &'a str,
) -> impl Iterator<Item = &'a LanInterface> + 'a {
    let matches_name = |left: &str, right: &str| {
        if cfg!(windows) {
            left.eq_ignore_ascii_case(right.trim())
        } else {
            left == right.trim()
        }
    };
    let mut addresses = HashSet::new();
    interfaces.iter().filter(move |link| {
        !matches_name(&link.name, excluded)
            && requested.is_none_or(|name| matches_name(&link.name, name))
            && addresses.insert((link.name.as_str(), link.broadcast))
    })
}

async fn send_to_lans<'a>(
    mac: MacAddress,
    interfaces: impl Iterator<Item = &'a LanInterface>,
) -> Result<(), WakeSendError> {
    let mut interfaces = interfaces.peekable();
    if interfaces.peek().is_none() {
        return Err(WakeSendError::NoLanInterface);
    }
    let mut sockets = Vec::new();
    for link in interfaces {
        let local = SocketAddrV4::new(link.ipv4, 0);
        if let Ok(socket) = crate::bind_udp(local.into(), Some(&link.name)).await {
            // TTL 1 confines even a misrouted datagram to one hop.
            if socket.set_broadcast(true).is_ok() && socket.set_ttl(1).is_ok() {
                sockets.push((socket, link.broadcast));
            }
        }
    }
    if sockets.is_empty() {
        return Err(WakeSendError::SendFailed);
    }

    let payload = magic_packet(mac);
    let mut submitted = false;
    let _ = tokio::time::timeout(SEND_TIMEOUT, async {
        for round in 0..BURST_COUNT {
            if round != 0 {
                tokio::time::sleep(BURST_INTERVAL).await;
            }
            for (socket, broadcast) in &sockets {
                for port in WAKE_PORTS {
                    let destination = SocketAddrV4::new(*broadcast, port);
                    let result = socket.send_to(&payload, destination).await;
                    submitted |= matches!(result, Ok(n) if n == payload.len());
                }
            }
        }
    })
    .await;
    submitted.then_some(()).ok_or(WakeSendError::SendFailed)
}

fn magic_packet(mac: MacAddress) -> [u8; 102] {
    let mut packet = [0xff; 102];
    let (addresses, _) = packet[6..].as_chunks_mut::<6>();
    for slot in addresses {
        *slot = mac.0;
    }
    packet
}

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    windows,
    test
))]
fn excluded_interface(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let overlay = ["utun", "tun", "tap", "p2wlan", "p2r", "wintun", "wireguard"];
    let virtual_link = [
        "docker",
        "veth",
        "virbr",
        "vmnet",
        "vbox",
        "tailscale",
        "zerotier",
    ];
    let container_bridge = name.strip_prefix("br-").is_some_and(|suffix| {
        suffix.len() == 12 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    name == "lo"
        || name == "lo0"
        || container_bridge
        || overlay
            .iter()
            .chain(virtual_link.iter())
            .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests;
