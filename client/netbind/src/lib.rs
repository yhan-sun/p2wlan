//! Socket constructors that pin public-network traffic to a physical
//! interface so a system-wide TUN route cannot capture it.
//!
//! Applying the option before `bind` / `connect` is important: choosing a
//! source address alone does not override a more-specific TUN route on macOS,
//! and `no_proxy` only controls HTTP proxy discovery, not kernel routing.

use std::io;
use std::net::{IpAddr, SocketAddr};

#[cfg(target_os = "android")]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(target_os = "android")]
use std::sync::{Mutex, OnceLock};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// The no-fragment properties that were actually installed on one UDP
/// socket.  DPLPMTUD treats a missing property as an unsupported capability;
/// ordinary UDP traffic remains usable and keeps the platform default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpNoFragmentCapabilities {
    /// IPv4 datagrams use a socket-level DF setting.
    pub ipv4: bool,
    /// IPv6 datagrams cannot be source-fragmented by this socket.
    pub ipv6: bool,
}

impl UdpNoFragmentCapabilities {
    /// Return whether the socket is safe for a probe to this destination
    /// family.
    pub const fn supports(self, destination: IpAddr) -> bool {
        match destination {
            IpAddr::V4(_) => self.ipv4,
            IpAddr::V6(_) => self.ipv6,
        }
    }
}

/// The kernel route selected for one concrete destination.
///
/// This is deliberately a read-only, destination-scoped result. Callers may
/// use it to rank a candidate or emit diagnostics, but it must not be used to
/// permanently bind the daemon's single Direct socket to one interface: a
/// later peer can legitimately use another LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteResolution {
    /// Destination used for the lookup.
    pub destination: IpAddr,
    /// Interface index when the platform exposes it through the interface
    /// enumeration API.
    pub interface_index: Option<u32>,
    /// Platform interface alias associated with the preferred source address.
    pub interface_name: Option<String>,
    /// Source address the kernel would use for this destination.
    pub preferred_source: Option<IpAddr>,
    /// Next hop when the platform/API exposes it. The socket-probe fallback
    /// intentionally leaves this unknown.
    pub next_hop: Option<IpAddr>,
    /// Route metric when the platform/API exposes it.
    pub metric: Option<u32>,
}

/// Resolve the route for one destination without sending a packet.
///
/// A UDP `connect` only asks the kernel to select a route and source address;
/// it does not perform a network handshake. This gives Windows the same
/// destination-aware source selection used by `send_to`, without invoking
/// PowerShell or parsing mutable command output. Interface metadata is then
/// matched to the selected source address. Native interface indices are
/// returned where the platform API permits it.
pub fn resolve_route(destination: IpAddr) -> Option<RouteResolution> {
    let bind_addr = if destination.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let destination_addr = SocketAddr::new(destination, 9);
    let socket = std::net::UdpSocket::bind(bind_addr).ok()?;
    socket.connect(destination_addr).ok()?;
    let preferred_source = socket.local_addr().ok()?.ip();
    if preferred_source.is_unspecified() {
        return None;
    }

    let (interface_name, interface_index) = interface_metadata_for_address(preferred_source)
        .map(|(name, index)| (Some(name), index))
        .unwrap_or((None, None));
    Some(RouteResolution {
        destination,
        interface_index,
        interface_name,
        preferred_source: Some(preferred_source),
        next_hop: None,
        metric: None,
    })
}

fn interface_metadata_for_address(address: IpAddr) -> Option<(String, Option<u32>)> {
    let interfaces = if_addrs::get_if_addrs().ok()?;
    interfaces.into_iter().find_map(|interface| {
        let interface_address = match interface.addr {
            if_addrs::IfAddr::V4(value) => IpAddr::V4(value.ip),
            if_addrs::IfAddr::V6(value) => IpAddr::V6(value.ip),
        };
        if interface_address != address {
            return None;
        }
        let name = interface.name;
        let index = interface.index.or_else(|| interface_index_for_name(&name));
        Some((name, index))
    })
}

#[cfg(unix)]
fn interface_index_for_name(name: &str) -> Option<u32> {
    use std::ffi::CString;

    let name = CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(windows)]
fn interface_index_for_name(name: &str) -> Option<u32> {
    use std::mem::MaybeUninit;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    };

    let wide = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut luid = MaybeUninit::zeroed();
    let result = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), luid.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    let luid = unsafe { luid.assume_init() };
    let mut index = 0u32;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    (result == 0).then_some(index)
}

#[cfg(not(any(unix, windows)))]
fn interface_index_for_name(_name: &str) -> Option<u32> {
    None
}

#[cfg(target_os = "android")]
pub type AndroidSocketProtector = fn(RawFd) -> io::Result<()>;

#[cfg(target_os = "android")]
static ANDROID_SOCKET_PROTECTOR: OnceLock<Mutex<Option<AndroidSocketProtector>>> = OnceLock::new();

/// Install the Android `VpnService.protect(fd)` bridge before the daemon opens
/// any physical-network sockets.  Android's overlay route can overlap a real
/// LAN (for example, a router using 10.20.0.0/16), so source-address selection
/// alone is not enough to keep Direct UDP outside the VPN.
#[cfg(target_os = "android")]
pub fn set_android_socket_protector(protector: AndroidSocketProtector) {
    let slot = ANDROID_SOCKET_PROTECTOR.get_or_init(|| Mutex::new(None));
    *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(protector);
}

/// Remove the Android protector after the native daemon runtime has stopped.
#[cfg(target_os = "android")]
pub fn clear_android_socket_protector() {
    if let Some(slot) = ANDROID_SOCKET_PROTECTOR.get() {
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

/// Bind a nonblocking Tokio UDP socket, optionally pinned to `interface`.
pub async fn bind_udp(addr: SocketAddr, interface: Option<&str>) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    protect_android_socket(&socket)?;
    if let Some(interface) = normalized_interface(interface) {
        bind_socket_to_interface(&socket, addr.is_ipv4(), interface)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    // Configure the profile once, while the socket constructor still owns
    // the socket.  The returned Tokio socket is never temporarily toggled
    // between business sends and probes.
    configure_udp_no_fragment_socket(&socket, addr.is_ipv4());
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

/// Read the no-fragment profile from a live Tokio UDP socket.
///
/// This is intentionally a read-only operation.  It is used at exact Direct
/// path reconciliation time so DPLPMTUD can fail closed if a platform,
/// socket family, or socket replacement does not provide the profile that was
/// configured by the socket owner.
pub fn udp_no_fragment_capabilities(socket: &UdpSocket) -> UdpNoFragmentCapabilities {
    let Ok(local_addr) = socket.local_addr() else {
        return UdpNoFragmentCapabilities::default();
    };
    read_udp_no_fragment_socket(socket, local_addr.ip().is_ipv4())
}

/// Return whether this exact socket can send a no-fragment probe to the
/// destination family.
pub fn udp_no_fragment_supported(socket: &UdpSocket, destination: IpAddr) -> bool {
    udp_no_fragment_capabilities(socket).supports(destination)
}

fn configure_udp_no_fragment_socket(
    socket: &Socket,
    ipv4_socket: bool,
) -> UdpNoFragmentCapabilities {
    read_or_configure_udp_no_fragment_socket(socket, ipv4_socket, true)
}

fn read_udp_no_fragment_socket(socket: &UdpSocket, ipv4_socket: bool) -> UdpNoFragmentCapabilities {
    read_or_configure_udp_no_fragment_socket(socket, ipv4_socket, false)
}

fn read_or_configure_udp_no_fragment_socket<S: UdpSocketRaw>(
    socket: &S,
    ipv4_socket: bool,
    configure: bool,
) -> UdpNoFragmentCapabilities {
    if ipv4_socket {
        UdpNoFragmentCapabilities {
            ipv4: if configure {
                configure_ipv4_no_fragment(socket)
            } else {
                read_ipv4_no_fragment(socket)
            },
            ipv6: false,
        }
    } else {
        UdpNoFragmentCapabilities {
            ipv4: false,
            ipv6: if configure {
                configure_ipv6_no_fragment(socket)
            } else {
                read_ipv6_no_fragment(socket)
            },
        }
    }
}

/// The small raw-socket interface keeps the platform implementations below
/// explicit and makes it impossible for a probe path to mutate an option
/// through this read-only API.
#[cfg(unix)]
trait UdpSocketRaw: std::os::fd::AsRawFd {}

#[cfg(windows)]
trait UdpSocketRaw: std::os::windows::io::AsRawSocket {}

#[cfg(not(any(unix, windows)))]
trait UdpSocketRaw {}

impl UdpSocketRaw for Socket {}

impl UdpSocketRaw for UdpSocket {}

#[cfg(unix)]
fn configure_ipv4_no_fragment<S: UdpSocketRaw>(socket: &S) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return set_and_verify_unix_option(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        );
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    {
        return set_and_verify_unix_option(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_DONTFRAG,
            1,
        );
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(not(unix))]
fn configure_ipv4_no_fragment<S: UdpSocketRaw>(_socket: &S) -> bool {
    #[cfg(windows)]
    {
        return set_and_verify_windows_option(
            _socket,
            windows_sys::Win32::Networking::WinSock::IPPROTO_IP,
            windows_sys::Win32::Networking::WinSock::IP_DONTFRAGMENT,
            1,
        );
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(unix)]
fn read_ipv4_no_fragment<S: UdpSocketRaw>(socket: &S) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return read_unix_option(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
            == Some(libc::IP_PMTUDISC_PROBE);
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    {
        return read_unix_option(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_DONTFRAG)
            .is_some_and(|value| value != 0);
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(not(unix))]
fn read_ipv4_no_fragment<S: UdpSocketRaw>(_socket: &S) -> bool {
    #[cfg(windows)]
    {
        return read_windows_option(
            _socket,
            windows_sys::Win32::Networking::WinSock::IPPROTO_IP,
            windows_sys::Win32::Networking::WinSock::IP_DONTFRAGMENT,
        )
        .is_some_and(|value| value != 0);
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(unix)]
fn configure_ipv6_no_fragment<S: UdpSocketRaw>(socket: &S) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let pmtudisc = set_and_verify_unix_option(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_PROBE,
        );
        let dontfrag = set_and_verify_unix_option(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_DONTFRAG,
            1,
        );
        return pmtudisc && dontfrag;
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    {
        return set_and_verify_unix_option(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_DONTFRAG,
            1,
        );
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(not(unix))]
fn configure_ipv6_no_fragment<S: UdpSocketRaw>(_socket: &S) -> bool {
    #[cfg(windows)]
    {
        return set_and_verify_windows_option(
            _socket,
            windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6,
            windows_sys::Win32::Networking::WinSock::IPV6_DONTFRAG,
            1,
        );
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(unix)]
fn read_ipv6_no_fragment<S: UdpSocketRaw>(socket: &S) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let pmtudisc = read_unix_option(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
        ) == Some(libc::IPV6_PMTUDISC_PROBE);
        let dontfrag =
            read_unix_option(socket.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG)
                .is_some_and(|value| value != 0);
        return pmtudisc && dontfrag;
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    {
        return read_unix_option(socket.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG)
            .is_some_and(|value| value != 0);
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(not(unix))]
fn read_ipv6_no_fragment<S: UdpSocketRaw>(_socket: &S) -> bool {
    #[cfg(windows)]
    {
        return read_windows_option(
            _socket,
            windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6,
            windows_sys::Win32::Networking::WinSock::IPV6_DONTFRAG,
        )
        .is_some_and(|value| value != 0);
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(unix)]
fn set_and_verify_unix_option(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> bool {
    let value_bytes = value.to_ne_bytes();
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            value_bytes.as_ptr().cast(),
            value_bytes.len() as libc::socklen_t,
        )
    };
    result == 0 && read_unix_option(fd, level, option) == Some(value)
}

#[cfg(unix)]
fn read_unix_option(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    option: libc::c_int,
) -> Option<libc::c_int> {
    let mut value = 0i32;
    let mut value_len = std::mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut value_len,
        )
    };
    (result == 0).then_some(value)
}

#[cfg(windows)]
fn set_and_verify_windows_option<S: UdpSocketRaw>(
    socket: &S,
    level: i32,
    option: i32,
    value: i32,
) -> bool {
    use windows_sys::Win32::Networking::WinSock::{setsockopt, WSAGetLastError, SOCKET_ERROR};

    let value_bytes = value.to_ne_bytes();
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            level,
            option,
            value_bytes.as_ptr(),
            value_bytes.len() as i32,
        )
    };
    if result == SOCKET_ERROR {
        let _ = unsafe { WSAGetLastError() };
        return false;
    }
    read_windows_option(socket, level, option) == Some(value)
}

#[cfg(windows)]
fn read_windows_option<S: UdpSocketRaw>(socket: &S, level: i32, option: i32) -> Option<i32> {
    use windows_sys::Win32::Networking::WinSock::{getsockopt, SOCKET_ERROR};

    let mut value = 0i32;
    let mut value_len = std::mem::size_of_val(&value) as i32;
    let result = unsafe {
        getsockopt(
            socket.as_raw_socket() as _,
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut value_len,
        )
    };
    (result != SOCKET_ERROR).then_some(value)
}

/// Connect to a resolved TCP endpoint, optionally pinned to `interface`.
/// Loopback destinations deliberately ignore the interface so local control
/// and test servers remain reachable.
pub async fn connect_tcp_addr(addr: SocketAddr, interface: Option<&str>) -> io::Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    protect_android_socket(&socket)?;
    if !addr.ip().is_loopback() {
        if let Some(interface) = normalized_interface(interface) {
            bind_socket_to_interface(&socket, addr.is_ipv4(), interface)?;
        }
    }
    socket.set_nonblocking(true)?;
    let stream: std::net::TcpStream = socket.into();
    TcpSocket::from_std_stream(stream).connect(addr).await
}

#[cfg(target_os = "android")]
fn protect_android_socket(socket: &Socket) -> io::Result<()> {
    let slot = ANDROID_SOCKET_PROTECTOR.get_or_init(|| Mutex::new(None));
    let protector =
        (*slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Android VPN socket protector is not installed",
            )
        })?;
    protector(socket.as_raw_fd())
}

#[cfg(not(target_os = "android"))]
fn protect_android_socket(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

/// Resolve and connect to a host, trying every address in resolver order.
pub async fn connect_tcp_host(
    host: &str,
    port: u16,
    interface: Option<&str>,
) -> io::Result<TcpStream> {
    let addresses = tokio::net::lookup_host((host, port)).await?;
    let mut last_error = None;
    for addr in addresses {
        match connect_tcp_addr(addr, interface).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("resolver returned no addresses for {host}:{port}"),
        )
    }))
}

fn normalized_interface(interface: Option<&str>) -> Option<&str> {
    interface.map(str::trim).filter(|name| !name.is_empty())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_socket_to_interface(socket: &Socket, _ipv4: bool, interface: &str) -> io::Result<()> {
    socket.bind_device(Some(interface.as_bytes()))
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
fn bind_socket_to_interface(socket: &Socket, ipv4: bool, interface: &str) -> io::Result<()> {
    use std::ffi::CString;
    use std::num::NonZeroU32;

    let interface = CString::new(interface).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains a NUL byte",
        )
    })?;
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    let index = NonZeroU32::new(index).ok_or_else(io::Error::last_os_error)?;
    if ipv4 {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
}

#[cfg(windows)]
fn bind_socket_to_interface(socket: &Socket, ipv4: bool, interface: &str) -> io::Result<()> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    };
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF,
        SOCKET_ERROR,
    };

    let wide = interface
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut luid = MaybeUninit::zeroed();
    let alias_result = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), luid.as_mut_ptr()) };
    if alias_result != 0 {
        return Err(io::Error::from_raw_os_error(alias_result as i32));
    }
    let luid = unsafe { luid.assume_init() };
    let mut index = 0u32;
    let index_result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if index_result != 0 {
        return Err(io::Error::from_raw_os_error(index_result as i32));
    }

    // Windows documents IP_UNICAST_IF as network byte order; the IPv6 option
    // uses the host-order interface index.
    let option_index = if ipv4 { index.to_be() } else { index };
    let (level, option) = if ipv4 {
        (IPPROTO_IP, IP_UNICAST_IF)
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF)
    };
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            (&option_index as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    } else {
        Ok(())
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    windows
)))]
fn bind_socket_to_interface(_socket: &Socket, _ipv4: bool, interface: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("binding sockets to interface '{interface}' is unsupported on this platform"),
    ))
}

/// Whether the destination should bypass interface pinning.
pub fn is_local_destination(address: IpAddr) -> bool {
    address.is_loopback() || address.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_tcp_ignores_an_invalid_public_interface() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = connect_tcp_addr(
            listener.local_addr().unwrap(),
            Some("definitely-not-a-real-interface"),
        )
        .await;
        assert!(stream.is_ok());
    }

    #[tokio::test]
    async fn invalid_interface_fails_closed_for_udp() {
        let result = bind_udp(
            "0.0.0.0:0".parse().unwrap(),
            Some("definitely-not-a-real-interface"),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn udp_no_fragment_profile_is_installed_once_and_read_back() {
        let ipv4 = bind_udp("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let ipv4_profile = udp_no_fragment_capabilities(&ipv4);
        assert_eq!(ipv4_profile, udp_no_fragment_capabilities(&ipv4));

        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
            windows
        ))]
        assert!(
            ipv4_profile.ipv4,
            "IPv4 no-fragment profile was not verified"
        );

        let ipv6 = bind_udp("[::1]:0".parse().unwrap(), None).await.unwrap();
        let ipv6_profile = udp_no_fragment_capabilities(&ipv6);
        assert_eq!(ipv6_profile, udp_no_fragment_capabilities(&ipv6));

        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
            windows
        ))]
        assert!(
            ipv6_profile.ipv6,
            "IPv6 no-fragment profile was not verified"
        );
    }

    #[test]
    fn route_resolution_is_destination_scoped_and_does_not_send() {
        let route = resolve_route(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .expect("loopback route should be available");
        assert_eq!(route.destination, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(
            route.preferred_source,
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
        assert!(route.next_hop.is_none());
        assert!(route.metric.is_none());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_udp_socket_reports_the_requested_bound_interface() {
        use std::ffi::CString;

        let socket = bind_udp("0.0.0.0:0".parse().unwrap(), Some("lo0"))
            .await
            .unwrap();
        let expected = unsafe { libc::if_nametoindex(CString::new("lo0").unwrap().as_ptr()) };
        let actual = socket2::SockRef::from(&socket)
            .device_index_v4()
            .unwrap()
            .map(|index| index.get());
        assert_eq!(actual, Some(expected));
    }
}
