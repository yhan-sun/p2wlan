use crate::Config;
use sha2::{Digest, Sha256};
use std::io;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, SetLastError, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Threading::CreateMutexW;

/// A cross-session lease shared by elevated desktop and SCM daemons. The
/// mutex handle itself keeps the named object alive; no OS thread owns it.
pub struct WindowsIdentityLease(HANDLE);

impl WindowsIdentityLease {
    pub fn acquire(config: &Config) -> io::Result<Self> {
        let key = zeroize::Zeroizing::new(
            hex::decode(&config.node.private_key).map_err(|_| invalid_key())?,
        );
        if key.len() != 32 {
            return Err(invalid_key());
        }
        let mut identity = Sha256::new();
        identity.update(b"p2wlan/windows-daemon-lock/v1\0");
        identity.update(key.as_slice());
        identity.update(
            config
                .control
                .server_url
                .trim()
                .trim_end_matches('/')
                .as_bytes(),
        );
        identity.update(b"\0");
        identity.update(config.network.network_id.as_bytes());
        let name = format!("Global\\P2WLAN-device-{}", hex::encode(identity.finalize()));
        Self::create(&name)
    }

    pub fn acquire_provisioning() -> io::Result<Self> {
        Self::create("Global\\P2WLAN-service-provisioning")
    }

    fn create(name: &str) -> io::Result<Self> {
        let name = super::windows_service_paths::wide(name);
        let descriptor_text =
            super::windows_service_paths::wide("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)");
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            SetLastError(ERROR_SUCCESS);
            CreateMutexW(&attrs, 0, name.as_ptr())
        };
        let code = unsafe { GetLastError() };
        unsafe { LocalFree(descriptor) };
        if handle.is_null() {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let lease = Self(handle);
        if code == ERROR_ALREADY_EXISTS {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "P2WLAN device identity is already in use",
            ));
        }
        Ok(lease)
    }
}

impl Drop for WindowsIdentityLease {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Same enrollment in two local profiles. The registration is scoped to the
/// network, WireGuard public key and configured Control server.
pub fn same_windows_device(first: &Config, second: &Config) -> bool {
    first
        .node
        .public_key
        .eq_ignore_ascii_case(&second.node.public_key)
        && first.network.network_id == second.network.network_id
        && first.control.server_url.trim().trim_end_matches('/')
            == second.control.server_url.trim().trim_end_matches('/')
}

fn invalid_key() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid configured WireGuard private key",
    )
}
