use crate::error::{DaemonError, Result};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use zeroize::{Zeroize, Zeroizing};

struct DpapiOutput(CRYPT_INTEGER_BLOB);

impl Drop for DpapiOutput {
    fn drop(&mut self) {
        let blob = &self.0;
        if !blob.pbData.is_null() {
            // DPAPI allocates the reported buffer with the LocalAlloc family.
            unsafe {
                std::slice::from_raw_parts_mut(blob.pbData, blob.cbData as usize).zeroize();
                LocalFree(blob.pbData.cast());
            }
        }
    }
}

fn run(input: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut owned = Zeroizing::new(input.to_vec());
    let input = CRYPT_INTEGER_BLOB {
        cbData: owned.len() as u32,
        pbData: owned.as_mut_ptr(),
    };
    let mut output = DpapiOutput(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    });
    // The descriptors and their backing buffers remain valid for the call.
    // No UI and no machine-wide flag: use the current user's DPAPI profile.
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                null(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &input,
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    let blob = &output.0;
    if ok == 0 || blob.pbData.is_null() || blob.cbData == 0 {
        return Err(DaemonError::Config(
            "Windows DPAPI could not process the device identity for this user".into(),
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) };
    Ok(Zeroizing::new(bytes.to_vec()))
}

pub(super) fn protect(input: &[u8]) -> Result<Vec<u8>> {
    Ok(run(input, true)?.to_vec())
}

pub(super) fn unprotect(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    run(input, false)
}
