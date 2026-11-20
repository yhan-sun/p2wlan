use std::io;
use std::mem::{size_of, MaybeUninit};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetIfEntry2Ex, MibIfEntryNormalWithoutStatistics, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::{
    IfOperStatusUp, NdisPhysicalMediumNative802_11, NdisPhysicalMediumWirelessLan,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

use super::{LinkMetadata, MacAddress};

pub(super) fn link_metadata() -> io::Result<LinkMetadata> {
    const INITIAL_BYTES: usize = 15_000;
    const MAX_ADAPTER_BYTES: usize = 4 * 1024 * 1024;
    let mut bytes = INITIAL_BYTES;
    // A typed buffer preserves native alignment. Pointers returned by the
    // API stay valid only while this buffer is alive.
    for _ in 0..3 {
        let count = bytes.div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::new();
        buffer.try_reserve_exact(count).map_err(io::Error::other)?;
        buffer.resize_with(count, MaybeUninit::uninit);
        let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut length = (count * size_of::<IP_ADAPTER_ADDRESSES_LH>()) as u32;
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                ptr::null_mut(),
                head,
                &mut length,
            )
        };
        match status {
            ERROR_SUCCESS => {
                let mut metadata = LinkMetadata::new();
                let mut current = head;
                while let Some(adapter) = unsafe { current.as_ref() } {
                    if let Some((index, mac, wired)) = ethernet_or_wifi(adapter) {
                        metadata.insert(index, (mac, wired));
                    }
                    current = adapter.Next;
                }
                return Ok(metadata);
            }
            ERROR_NO_DATA => return Ok(LinkMetadata::new()),
            ERROR_BUFFER_OVERFLOW if (length as usize) <= MAX_ADAPTER_BYTES => {
                bytes = length as usize;
            }
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
    Err(io::Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32))
}

fn ethernet_or_wifi(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Option<(u32, MacAddress, bool)> {
    if adapter.OperStatus != IfOperStatusUp
        || adapter.PhysicalAddressLength != 6
        || !matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
    {
        return None;
    }
    let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
    if index == 0 {
        return None;
    }

    // MIB_IF_ROW2's first two bitfields are HardwareInterface and
    // FilterInterface. An Ethernet type alone also permits virtual NICs.
    const HARDWARE_INTERFACE: u8 = 0x01;
    const FILTER_INTERFACE: u8 = 0x02;
    let mut row = unsafe { std::mem::zeroed::<MIB_IF_ROW2>() };
    row.InterfaceIndex = index;
    if unsafe { GetIfEntry2Ex(MibIfEntryNormalWithoutStatistics, &mut row) } != ERROR_SUCCESS
        || row.InterfaceAndOperStatusFlags._bitfield & (HARDWARE_INTERFACE | FILTER_INTERFACE)
            != HARDWARE_INTERFACE
    {
        return None;
    }
    let wifi = adapter.IfType == IF_TYPE_IEEE80211
        || row.PhysicalMediumType == NdisPhysicalMediumNative802_11
        || row.PhysicalMediumType == NdisPhysicalMediumWirelessLan;
    let mut bytes = [0; 6];
    bytes.copy_from_slice(&adapter.PhysicalAddress[..6]);
    let mac = MacAddress::from_bytes(bytes).ok()?;
    Some((index, mac, !wifi))
}
