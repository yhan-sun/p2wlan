use super::NodeConfig;
use crate::error::{DaemonError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[cfg(windows)]
#[path = "identity_protection/dpapi.rs"]
mod dpapi;
#[cfg(unix)]
#[path = "identity_protection/key_file.rs"]
mod key_file;

const WRAPPED_PREFIX: &str = "p2wlan-sealed-v1:";
const MAX_WRAPPED_BYTES: usize = 4096;

/// How a persisted profile protects its device identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityProtection {
    /// A dedicated random wrapping key mounted outside the profile.
    KeyFile { path: PathBuf },
    /// Windows DPAPI bound to the current user.
    WindowsDpapi,
}

fn invalid_identity() -> DaemonError {
    DaemonError::Config("invalid protected device identity or public key mismatch".into())
}

impl IdentityProtection {
    pub(super) fn seal(&self, node: &NodeConfig) -> Result<NodeConfig> {
        let mut secret = Zeroizing::new([0u8; 64]);
        hex::decode_to_slice(&node.private_key, &mut secret[..32])
            .map_err(|_| invalid_identity())?;
        let length = if node.ed25519_private_key.is_empty() {
            32
        } else {
            hex::decode_to_slice(&node.ed25519_private_key, &mut secret[32..])
                .map_err(|_| invalid_identity())?;
            64
        };
        let secret = &secret[..length];
        verify_public_keys(node, secret)?;
        let ciphertext = self.wrap(secret)?;
        if ciphertext.len() > MAX_WRAPPED_BYTES {
            return Err(invalid_identity());
        }
        Ok(NodeConfig {
            private_key: format!("{WRAPPED_PREFIX}{}", hex::encode(ciphertext)),
            ed25519_private_key: String::new(),
            node_id: node.node_id.clone(),
            public_key: node.public_key.clone(),
            ed25519_public_key: node.ed25519_public_key.clone(),
            device_name: node.device_name.clone(),
            platform: node.platform.clone(),
        })
    }

    pub(super) fn open(&self, node: &mut NodeConfig) -> Result<()> {
        let encoded = node
            .private_key
            .strip_prefix(WRAPPED_PREFIX)
            .ok_or_else(invalid_identity)?;
        if !node.ed25519_private_key.is_empty() || encoded.len() > MAX_WRAPPED_BYTES * 2 {
            return Err(invalid_identity());
        }
        let ciphertext = hex::decode(encoded).map_err(|_| invalid_identity())?;
        let secret = self.unwrap(&ciphertext)?;
        verify_public_keys(node, &secret)?;
        node.private_key = hex::encode(&secret[..32]);
        node.ed25519_private_key = hex::encode(&secret[32..]);
        Ok(())
    }

    fn wrap(&self, secret: &[u8]) -> Result<Vec<u8>> {
        match self {
            #[cfg(unix)]
            Self::KeyFile { path } => key_file::seal(path, secret),
            #[cfg(windows)]
            Self::WindowsDpapi => dpapi::protect(secret),
            #[allow(unreachable_patterns)]
            _ => Err(unsupported_backend()),
        }
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            #[cfg(unix)]
            Self::KeyFile { path } => key_file::open(path, ciphertext),
            #[cfg(windows)]
            Self::WindowsDpapi => dpapi::unprotect(ciphertext),
            #[allow(unreachable_patterns)]
            _ => Err(unsupported_backend()),
        }
    }
}

pub(super) fn contains_wrapped_key(node: &NodeConfig) -> bool {
    is_wrapped_key(&node.private_key)
}

pub(super) fn is_wrapped_key(value: &str) -> bool {
    value.starts_with(WRAPPED_PREFIX)
}

fn unsupported_backend() -> DaemonError {
    DaemonError::Config("device identity protection backend is unavailable on this platform".into())
}

fn verify_public_keys(node: &NodeConfig, secret: &[u8]) -> Result<()> {
    if !matches!(secret.len(), 32 | 64) {
        return Err(invalid_identity());
    }
    let private: &[u8; 32] = secret[..32].try_into().map_err(|_| invalid_identity())?;
    let x25519 = p2pnet_crypto::DhKeyPair::from_private_key(*private);
    let expected = hex::encode(x25519.public_key());
    if !node.public_key.eq_ignore_ascii_case(&expected) {
        return Err(invalid_identity());
    }
    if secret.len() == 64 {
        let private = secret[32..].try_into().map_err(|_| invalid_identity())?;
        let ed25519 = p2pnet_crypto::Ed25519KeyPair::from_private_key(private);
        if !node
            .ed25519_public_key
            .eq_ignore_ascii_case(&hex::encode(ed25519.public_key()))
        {
            return Err(invalid_identity());
        }
    } else if !node.ed25519_public_key.is_empty() {
        return Err(invalid_identity());
    }
    Ok(())
}
