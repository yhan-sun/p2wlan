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
    use std::os::unix::fs::OpenOptionsExt;

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
    fn rejects_invalid_mode_and_closes_consumed_fd() {
        for fd in [
            open_dev_null(true, false, true, true),
            open_dev_null(true, true, false, true),
            open_dev_null(true, true, true, false),
        ] {
            let raw_fd = fd.as_raw_fd();
            assert!(validate_ohos_vpn_fd(fd).is_err());
            let result = unsafe { libc::fcntl(raw_fd, libc::F_GETFD, 0) };
            let error = std::io::Error::last_os_error().raw_os_error();
            assert_eq!(result, -1, "invalid OwnedFd must be closed on failure");
            assert_eq!(error, Some(libc::EBADF));
        }
    }
}
