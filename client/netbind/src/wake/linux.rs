use std::fs;
use std::io;
use std::path::Path;

use super::{excluded_interface, LinkMetadata};

pub(super) fn link_metadata() -> io::Result<LinkMetadata> {
    let mut metadata = LinkMetadata::new();
    let entries = match fs::read_dir("/sys/class/net") {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(metadata),
        Err(error) => return Err(error),
    };
    for interface in entries.flatten() {
        let path = interface.path();
        if !is_lan_link(&path, 0) {
            continue;
        }
        let Some(index) = read::<u32>(&path.join("ifindex")) else {
            continue;
        };
        if let Some(mac) = read(&path.join("address")) {
            let wired = !path.join("wireless").exists() && !path.join("phy80211").exists();
            metadata.insert(index, (mac, wired));
        }
    }
    Ok(metadata)
}

fn read<T: std::str::FromStr>(path: &Path) -> Option<T> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn is_lan_link(path: &Path, depth: usize) -> bool {
    const MAX_LOWER_LINK_DEPTH: usize = 8;
    const ARPHRD_ETHER: u16 = 1;
    if depth >= MAX_LOWER_LINK_DEPTH
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(excluded_interface)
        || read(&path.join("type")) != Some(ARPHRD_ETHER)
        || path.join("tun_flags").exists()
    {
        return false;
    }
    if path.join("device").exists() {
        return true;
    }

    // OpenWrt commonly assigns the IPv4 address to a software bridge or
    // VLAN. Accept those links only when a lower layer leads to a real NIC.
    let is_vlan = fs::read_to_string(path.join("uevent"))
        .is_ok_and(|value| value.lines().any(|line| line == "DEVTYPE=vlan"));
    if !(is_vlan || path.join("bridge").exists() || path.join("bonding").exists()) {
        return false;
    }
    fs::read_dir(path).is_ok_and(|mut entries| {
        entries.any(|entry| {
            let Ok(entry) = entry else { return false };
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("lower_"))
                && fs::canonicalize(entry.path()).is_ok_and(|lower| is_lan_link(&lower, depth + 1))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn bridge_requires_a_non_overlay_physical_lower_link() -> io::Result<()> {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("p2wlan-wake-bridge-{}-{time}", std::process::id()));
        fs::create_dir(&directory)?;
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let bridge = directory.join("br-lan");
        let vlan = directory.join("eth0.20");
        let ethernet = directory.join("eth0");
        let overlay = directory.join("renamed-overlay");
        for nic in [&bridge, &vlan, &ethernet, &overlay] {
            fs::create_dir(nic)?;
            fs::write(nic.join("type"), b"1\n")?;
        }
        fs::create_dir(bridge.join("bridge"))?;
        fs::create_dir(ethernet.join("device"))?;
        fs::create_dir(overlay.join("device"))?;
        fs::write(overlay.join("tun_flags"), b"0x2\n")?;
        fs::write(vlan.join("uevent"), b"DEVTYPE=vlan\n")?;
        symlink(&overlay, bridge.join("lower_renamed-overlay"))?;
        assert!(!is_lan_link(&bridge, 0));

        symlink(&ethernet, vlan.join("lower_eth0"))?;
        symlink(&vlan, bridge.join("lower_eth0.20"))?;
        assert!(is_lan_link(&bridge, 0));
        Ok(())
    }
}
