use crate::error::{DaemonError, Result};
use rand::{rngs::OsRng, RngCore};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

const AAD: &[u8] = b"P2WLAN device identity wrapping v1";

fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let invalid = || {
        DaemonError::Config(
        "identity wrapping key must be an absolute path to a private regular file with 64 hex digits".into(),
    )
    };
    if !path.is_absolute() {
        return Err(invalid());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| {
            DaemonError::Config(format!("identity wrapping key is unavailable: {err}"))
        })?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || !matches!(metadata.len(), 64..=66)
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || (uid != 0 && metadata.uid() != uid)
    {
        return Err(invalid());
    }
    // Read through the checked descriptor with a one-byte overrun sentinel.
    let mut encoded = Zeroizing::new(Vec::with_capacity(67));
    file.take(67)
        .read_to_end(&mut encoded)
        .map_err(|_| invalid())?;
    let key_bytes = encoded
        .strip_suffix(b"\r\n")
        .or_else(|| encoded.strip_suffix(b"\n"))
        .unwrap_or(&encoded);
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(key_bytes, &mut key[..]).map_err(|_| invalid())?;
    Ok(key)
}

pub(super) fn seal(path: &Path, secret: &[u8]) -> Result<Vec<u8>> {
    let key = read_key(path)?;
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| DaemonError::Config("cannot generate identity wrapping nonce".into()))?;
    let sealed = p2pnet_crypto::encrypt(&key, &nonce, AAD, secret)
        .map_err(|_| DaemonError::Config("failed to wrap device identity".into()))?;
    let mut result = Vec::with_capacity(nonce.len() + sealed.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&sealed);
    Ok(result)
}

pub(super) fn open(path: &Path, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let invalid = || DaemonError::Config("cannot unlock protected device identity".into());
    if !matches!(ciphertext.len(), 60 | 92) {
        return Err(invalid());
    }
    let key = read_key(path)?;
    let (nonce, sealed) = ciphertext.split_at(12);
    p2pnet_crypto::decrypt(&key, nonce.try_into().map_err(|_| invalid())?, AAD, sealed)
        .map(Zeroizing::new)
        .map_err(|_| invalid())
}
