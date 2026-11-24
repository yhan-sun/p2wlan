//! Shared Unix-fd validation for the HarmonyOS VPN descriptor boundary.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::error::{Error, Result};

/// Accept only an already nonblocking, read-write VPN descriptor marked
/// close-on-exec. The fd is consumed on both success and failure, so an
/// invalid descriptor is closed by `OwnedFd` when this function returns.
pub(crate) fn validate_ohos_vpn_fd(owned_fd: OwnedFd) -> Result<OwnedFd> {
    let raw_fd = owned_fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    if flags & libc::O_ACCMODE != libc::O_RDWR {
        return Err(Error::Platform(
            "HarmonyOS VPN TUN fd is not open for both read and write".to_string(),
        ));
    }
    if flags & libc::O_NONBLOCK == 0 {
        return Err(Error::Platform(
            "HarmonyOS VPN TUN fd is not nonblocking".to_string(),
        ));
    }

    let descriptor_flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD, 0) };
    if descriptor_flags < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    if descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(Error::Platform(
            "HarmonyOS VPN TUN fd is not close-on-exec".to_string(),
        ));
    }

    Ok(owned_fd)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn open_dev_null(read: bool, write: bool, nonblocking: bool, close_on_exec: bool) -> OwnedFd {
        let mut options = OpenOptions::new();
        options.read(read).write(write);
        if nonblocking {
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options.open("/dev/null").expect("open /dev/null");
        if !close_on_exec {
            let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) };
            assert_eq!(result, 0, "clear close-on-exec for negative test");
        }
        file.into()
    }

    #[test]
    fn accepts_read_write_nonblocking_close_on_exec_fd() {
        let fd = open_dev_null(true, true, true, true);
        assert!(validate_ohos_vpn_fd(fd).is_ok());
    }

    #[test]
    fn rejects_read_only_fd() {
        assert!(validate_ohos_vpn_fd(open_dev_null(true, false, true, true)).is_err());
    }

    #[test]
    fn rejects_invalid_flags_and_closes_consumed_fd() {
        for (nonblocking, close_on_exec) in [(false, true), (true, false)] {
            let (candidate, mut peer) = UnixStream::pair().unwrap();
            candidate.set_nonblocking(nonblocking).unwrap();
            if !close_on_exec {
                let result = unsafe { libc::fcntl(candidate.as_raw_fd(), libc::F_SETFD, 0) };
                assert_eq!(result, 0);
            }
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let invalid_fd: OwnedFd = candidate.into();
            assert!(validate_ohos_vpn_fd(invalid_fd).is_err());
            // EOF proves the particular socket was closed even if another
            // test immediately reuses its descriptor number.
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }
}
