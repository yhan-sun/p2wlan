//! Read-only IP Helper snapshots. No callback, socket binding or connection
//! state lives here. The existing cached snapshot and lifecycle debounce own
//! sampling, so Windows uses the same recovery path as other desktop hosts.

use std::mem::{size_of, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIpForwardTable2, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_PROP_VIRTUAL,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET, SOCKET_ADDRESS,
};

use super::network_signature::{self, WindowsAdapter, WindowsDefaultRoute};

const MAX_ADAPTER_BYTES: usize = 1024 * 1024;
const MAX_ADAPTERS: usize = 256;
const MAX_ADDRESSES: usize = 4096;
const MAX_ROUTES: usize = 16384;

pub(super) fn network_signature(excluded: &[String]) -> Option<Vec<String>> {
    let adapters = adapters()?;
    let routes = default_routes()?;
    Some(network_signature::windows_signature(
        &adapters, &routes, excluded,
    ))
}

// Using the native structure as allocation element preserves its alignment on
// every Windows target. Vec owns and frees the buffer on every return path.
struct AdapterBuffer {
    storage: Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>,
    bytes: usize,
}

impl AdapterBuffer {
    fn new(bytes: usize) -> Option<Self> {
        if bytes == 0 || bytes > MAX_ADAPTER_BYTES {
            return None;
        }
        let elements = bytes.div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut storage = Vec::new();
        storage.try_reserve_exact(elements).ok()?;
        storage.resize_with(elements, MaybeUninit::zeroed);
        Some(Self { storage, bytes })
    }

    fn pointer(&mut self) -> *mut IP_ADAPTER_ADDRESSES_LH {
        self.storage.as_mut_ptr().cast()
    }

    // Only called for the native integer/pointer structures filled by IP
    // Helper, or u16. Copying avoids creating references into a linked buffer.
    fn read<T: Copy>(&self, pointer: *const T) -> Option<T> {
        let offset = (pointer as usize).checked_sub(self.storage.as_ptr() as usize)?;
        if offset.checked_add(size_of::<T>())? > self.bytes {
            return None;
        }
        // SAFETY: the pointer lies entirely in our initialized owned buffer;
        // every caller uses a native structure with no invalid bit patterns.
        Some(unsafe { ptr::read_unaligned(pointer) })
    }

    fn name(&self, pointer: *const u16) -> Option<String> {
        let mut name = Vec::new();
        for offset in 0..257 {
            let codepoint = self.read(pointer.wrapping_add(offset))?;
            if codepoint == 0 {
                return Some(String::from_utf16_lossy(&name));
            }
            name.push(codepoint);
        }
        None
    }

    fn address(&self, address: SOCKET_ADDRESS) -> Option<IpAddr> {
        let family = self.read(address.lpSockaddr.cast::<u16>())?;
        match family {
            AF_INET if address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN>() => {
                let value = self.read(address.lpSockaddr.cast::<SOCKADDR_IN>())?;
                // SAFETY: AF_INET identifies the IPv4 address union member.
                Some(IpAddr::V4(Ipv4Addr::from(
                    unsafe { value.sin_addr.S_un.S_addr }.to_ne_bytes(),
                )))
            }
            AF_INET6 if address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN6>() => {
                let value = self.read(address.lpSockaddr.cast::<SOCKADDR_IN6>())?;
                // SAFETY: AF_INET6 identifies the IPv6 byte representation.
                Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                    value.sin6_addr.u.Byte
                })))
            }
            _ => None,
        }
    }
}

fn adapters() -> Option<Vec<WindowsAdapter>> {
    let mut bytes = 15 * 1024;
    // DHCP can change the required buffer between calls. Bound both memory
    // and retries instead of blocking a lifecycle sampler indefinitely.
    for _ in 0..3 {
        let mut buffer = AdapterBuffer::new(bytes)?;
        let mut supplied = bytes as u32;
        // SAFETY: writable aligned allocation of supplied bytes; no callback
        // or pointer escapes this synchronous IP Helper invocation.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                ptr::null(),
                buffer.pointer(),
                &mut supplied,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            bytes = supplied as usize;
            continue;
        }
        if result != ERROR_SUCCESS {
            return None;
        }
        buffer.bytes = buffer.bytes.min(supplied as usize);
        return read_adapters(&mut buffer);
    }
    None
}

fn read_adapters(buffer: &mut AdapterBuffer) -> Option<Vec<WindowsAdapter>> {
    let mut result = Vec::new();
    let mut current = buffer.pointer();
    let mut address_count = 0;
    for _ in 0..MAX_ADAPTERS {
        if current.is_null() {
            return Some(result);
        }
        let adapter = buffer.read(current)?;
        let name = buffer.name(adapter.FriendlyName)?;
        let mut addresses = Vec::new();
        let mut address = adapter.FirstUnicastAddress;
        while !address.is_null() {
            address_count += 1;
            if address_count > MAX_ADDRESSES {
                return None;
            }
            let unicast: IP_ADAPTER_UNICAST_ADDRESS_LH = buffer.read(address)?;
            if let Some(ip) = buffer.address(unicast.Address) {
                addresses.push((ip, unicast.OnLinkPrefixLength));
            }
            address = unicast.Next;
        }
        let network = adapter.NetworkGuid;
        result.push(WindowsAdapter {
            name,
            // SAFETY: Value is the documented full-width LUID representation.
            luid: unsafe { adapter.Luid.Value },
            up: adapter.OperStatus == IfOperStatusUp,
            tunnel: matches!(
                adapter.IfType,
                IF_TYPE_PROP_VIRTUAL | IF_TYPE_SOFTWARE_LOOPBACK | IF_TYPE_TUNNEL
            ),
            network_id: format!(
                "{:08x}-{:04x}-{:04x}-{}",
                network.data1,
                network.data2,
                network.data3,
                hex::encode(network.data4)
            ),
            ipv4_metric: adapter.Ipv4Metric,
            ipv6_metric: adapter.Ipv6Metric,
            addresses,
        });
        current = adapter.Next;
    }
    None
}

struct RouteTable(*mut MIB_IPFORWARD_TABLE2);

impl Drop for RouteTable {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetIpForwardTable2 allocated this table; this guard is
            // its sole owner and outlives every copied row.
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
}

fn default_routes() -> Option<Vec<WindowsDefaultRoute>> {
    let mut table = RouteTable(ptr::null_mut());
    // SAFETY: output pointer is valid and starts null; RouteTable frees the
    // IP Helper allocation on success and every later early return.
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table.0) } != ERROR_SUCCESS || table.0.is_null()
    {
        return None;
    }
    // SAFETY: a successful IP Helper result contains NumEntries rows. Use a
    // raw field address so a zero-row table never creates a one-row reference.
    let count = unsafe { (*table.0).NumEntries as usize };
    if count > MAX_ROUTES {
        return None;
    }
    let rows = unsafe { ptr::addr_of!((*table.0).Table).cast::<MIB_IPFORWARD_ROW2>() };
    let mut result = Vec::new();
    for index in 0..count {
        // SAFETY: index is inside the API's row count, bounded above, and the
        // allocation remains owned by table throughout this loop.
        let row = unsafe { ptr::read(rows.add(index)) };
        if row.DestinationPrefix.PrefixLength != 0 || row.Loopback != 0 {
            continue;
        }
        let Some((next_hop, scope)) = route_address(row.NextHop) else {
            continue;
        };
        result.push(WindowsDefaultRoute {
            // SAFETY: Value is the documented full-width LUID representation.
            luid: unsafe { row.InterfaceLuid.Value },
            index: row.InterfaceIndex,
            next_hop,
            scope,
            metric: row.Metric,
        });
    }
    Some(result)
}

fn route_address(address: SOCKADDR_INET) -> Option<(IpAddr, u32)> {
    // SAFETY: IP Helper initializes this tagged union; inspect its family
    // before reading the matching IPv4/IPv6 representation.
    unsafe {
        match address.si_family {
            AF_INET => Some((
                IpAddr::V4(Ipv4Addr::from(
                    address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                )),
                0,
            )),
            AF_INET6 => Some((
                IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte)),
                address.Ipv6.Anonymous.sin6_scope_id,
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::{
        IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR_IN6_0,
    };

    #[test]
    fn adapter_buffer_rejects_oversized_allocation_and_out_of_bounds_reads() {
        assert!(AdapterBuffer::new(MAX_ADAPTER_BYTES + 1).is_none());
        let mut buffer = AdapterBuffer::new(1024).unwrap();
        let pointer = buffer.pointer().cast::<u8>();
        assert_eq!(buffer.read(pointer), Some(0));
        assert_eq!(buffer.read(pointer.wrapping_add(1023)), Some(0));
        assert_eq!(buffer.read(pointer.wrapping_add(1024)), None);
        assert_eq!(buffer.read(pointer.wrapping_add(1023).cast::<u16>()), None);
        assert_eq!(buffer.read(ptr::null::<u16>()), None);
    }

    #[test]
    fn route_address_preserves_network_order_and_ipv6_scope() {
        let ipv4 = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes([192, 0, 2, 1]),
                    },
                },
                sin_zero: [0; 8],
            },
        };
        assert_eq!(route_address(ipv4), Some(("192.0.2.1".parse().unwrap(), 0)));
        let ipv6 = SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: "fe80::1".parse::<Ipv6Addr>().unwrap().octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 7 },
            },
        };
        assert_eq!(route_address(ipv6), Some(("fe80::1".parse().unwrap(), 7)));
    }
}
