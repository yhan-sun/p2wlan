use std::ffi::CStr;
use std::io;
use std::mem::offset_of;
use std::ptr;

use super::{LinkMetadata, MacAddress};

pub(super) fn link_metadata() -> io::Result<LinkMetadata> {
    let mut head = ptr::null_mut();
    // getifaddrs owns the linked list until freeifaddrs is called on its head.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Interfaces(*mut libc::ifaddrs);
    impl Drop for Interfaces {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let interfaces = Interfaces(head);
    let mut metadata = LinkMetadata::new();
    let mut current = interfaces.0;
    while let Some(interface) = unsafe { current.as_ref() } {
        current = interface.ifa_next;
        let address = interface.ifa_addr;
        if address.is_null()
            || i32::from(unsafe { (*address).sa_family }) != libc::AF_LINK
            || interface.ifa_name.is_null()
        {
            continue;
        }
        let name = unsafe { CStr::from_ptr(interface.ifa_name) }.to_bytes();
        // Darwin IP-capable hardware adapters are enN. awdl, llw, utun,
        // bridge and other virtual interfaces must not carry remote wake.
        let Some(suffix) = name.strip_prefix(b"en") else {
            continue;
        };
        if suffix.is_empty() || !suffix.iter().all(u8::is_ascii_digit) {
            continue;
        }
        if let Some((index, mac, wired)) = link_address(address) {
            metadata.insert(index, (mac, wired));
        }
    }
    Ok(metadata)
}

fn link_address(address: *const libc::sockaddr) -> Option<(u32, MacAddress, bool)> {
    const IFT_ETHER: u8 = 0x06;
    const IFT_IEEE80211: u8 = 0x47;

    // AF_LINK supplies a variable-length sockaddr_dl; validate the declared
    // length before reading the header or the bytes following the name.
    let header = offset_of!(libc::sockaddr_dl, sdl_data);
    let length = usize::from(unsafe { (*address).sa_len });
    if length < header {
        return None;
    }
    let link = address.cast::<libc::sockaddr_dl>();
    let (kind, name_len, addr_len, index) = unsafe {
        (
            (*link).sdl_type,
            (*link).sdl_nlen,
            (*link).sdl_alen,
            (*link).sdl_index,
        )
    };
    let start = header + usize::from(name_len);
    if !matches!(kind, IFT_ETHER | IFT_IEEE80211) || addr_len != 6 || start + 6 > length {
        return None;
    }
    let bytes = unsafe { address.cast::<u8>().add(start).cast::<[u8; 6]>().read() };
    let mac = MacAddress::from_bytes(bytes).ok()?;
    Some((u32::from(index), mac, kind == IFT_ETHER))
}
