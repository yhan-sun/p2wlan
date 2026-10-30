#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;

#[cfg(any(target_env = "ohos", all(unix, test)))]
mod diagnostics;
#[cfg(target_env = "ohos")]
mod lifecycle;
#[cfg(any(target_env = "ohos", test))]
mod shutdown;
#[cfg(any(target_env = "ohos", test))]
mod snapshot;
#[cfg(any(target_env = "ohos", test))]
pub use snapshot::{
    P2wlanStringListV1, P2wlanStringViewV1, P2wlanVpnIdentityV1, P2wlanVpnNetworkRequestV1,
    P2wlanVpnSettingsSnapshotV1, P2wlanVpnSettingsV1, P2wlanVpnStartRequestV1,
};

pub const ABI_VERSION: u32 = 1;
pub const STATUS_OK: i32 = 0;
pub const STATUS_NULL_OUTPUT: i32 = 1;
pub const STATUS_BAD_ARGUMENT: i32 = 2;
pub const STATUS_INVALID_REQUEST: i32 = 3;
pub const STATUS_TUN_FD_DUP_FAILED: i32 = 4;
pub const STATUS_TUN_FD_NOT_NONBLOCKING: i32 = 5;
pub const STATUS_ALREADY_RUNNING: i32 = 6;
pub const STATUS_ENGINE_BUSY: i32 = 7;
pub const STATUS_STALE_GENERATION: i32 = 8;
pub const STATUS_STALE_SETTINGS_SNAPSHOT: i32 = 9;
pub const STATUS_START_TIMEOUT: i32 = 10;
pub const STATUS_START_CANCELLED: i32 = 11;
pub const STATUS_IDENTITY_STORE_FAILED: i32 = 12;
pub const STATUS_ROUTE_PROOF_INVALID: i32 = 13;
pub const STATUS_CONFIG_INVALID: i32 = 14;
pub const STATUS_AUTH_FAILED: i32 = 15;
pub const STATUS_DAEMON_START_FAILED: i32 = 16;
pub const STATUS_STOPPED: i32 = 17;
pub const STATUS_DRAINING: i32 = 18;
pub const STATUS_UNKNOWN_IDENTITY: i32 = 19;
pub const STATUS_TUN_FD_INVALID_MODE: i32 = 20;
pub const STATUS_ENGINE_HISTORY_FULL: i32 = 21;
pub const STATUS_NETWORK_PREFLIGHT_FAILED: i32 = 22;

pub const STATUS_ENGINE_STARTING: i32 = 0;
pub const STATUS_ENGINE_READY: i32 = 1;
pub const STATUS_ENGINE_STOPPING: i32 = 2;
pub const STATUS_ENGINE_STOPPED: i32 = 3;
pub const STATUS_ENGINE_FAILED_BASE: i32 = 100;

const ENGINE_VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
const BUILD_TARGET: &[u8] = concat!(env!("P2WLAN_BUILD_TARGET"), "\0").as_bytes();
const BUILD_ARCH: &[u8] = concat!(env!("P2WLAN_BUILD_ARCH"), "\0").as_bytes();

/// Immutable metadata returned by the Harmony FFI v1 entry point.
///
/// All string pointers refer to static, NUL-terminated storage owned by this
/// library. Callers must copy the strings before unloading the library and
/// must not free or retain them beyond the library's process lifetime.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct P2wlanBuildInfoV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub engine_version: *const c_char,
    pub target: *const c_char,
    pub arch: *const c_char,
}

impl P2wlanBuildInfoV1 {
    fn current() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: core::mem::size_of::<Self>() as u32,
            engine_version: ENGINE_VERSION.as_ptr().cast(),
            target: BUILD_TARGET.as_ptr().cast(),
            arch: BUILD_ARCH.as_ptr().cast(),
        }
    }
}

/// Returns compile-time build metadata through the stable FFI v1 contract.
///
/// # Safety
/// `output` must be null or point to a writable, correctly aligned
/// `P2wlanBuildInfoV1`. On success the returned string pointers remain valid
/// for the lifetime of the loaded shared library and are never caller-owned.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_get_build_info_v1(output: *mut P2wlanBuildInfoV1) -> i32 {
    if output.is_null() {
        return STATUS_NULL_OUTPUT;
    }

    // SAFETY: the FFI caller promises a writable, aligned output structure.
    unsafe { output.write(P2wlanBuildInfoV1::current()) };
    STATUS_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    #[test]
    fn null_output_is_a_typed_error() {
        // SAFETY: null is an explicitly supported error input.
        let status = unsafe { p2wlan_harmony_get_build_info_v1(core::ptr::null_mut()) };
        assert_eq!(status, STATUS_NULL_OUTPUT);
    }

    #[test]
    fn metadata_uses_static_nul_terminated_strings() {
        let mut info = core::mem::MaybeUninit::<P2wlanBuildInfoV1>::uninit();
        // SAFETY: MaybeUninit points to writable, correctly aligned storage.
        let status = unsafe { p2wlan_harmony_get_build_info_v1(info.as_mut_ptr()) };
        assert_eq!(status, STATUS_OK);

        // SAFETY: the FFI call returned success and initialized every field.
        let info = unsafe { info.assume_init() };
        assert_eq!(info.abi_version, ABI_VERSION);
        assert_eq!(
            info.struct_size as usize,
            core::mem::size_of::<P2wlanBuildInfoV1>()
        );
        // SAFETY: the pointers refer to static NUL-terminated byte strings.
        assert_eq!(
            unsafe { CStr::from_ptr(info.engine_version) }
                .to_str()
                .unwrap(),
            env!("CARGO_PKG_VERSION")
        );
        // SAFETY: the pointers refer to static NUL-terminated byte strings.
        assert_eq!(
            unsafe { CStr::from_ptr(info.target) }.to_str().unwrap(),
            env!("P2WLAN_BUILD_TARGET")
        );
        // SAFETY: the pointers refer to static NUL-terminated byte strings.
        assert_eq!(
            unsafe { CStr::from_ptr(info.arch) }.to_str().unwrap(),
            env!("P2WLAN_BUILD_ARCH")
        );
    }
}
