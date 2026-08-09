use super::*;
use crate::client::RelayClient;
use crate::{RelayClientConfig, RelayCloseReason, RelayErrorCode, RelayMessage};
use std::time::Duration;

/// Create a dev-mode config for localhost testing.
fn dev_config() -> RelayServerConfig {
    RelayServerConfig {
        allow_insecure_plaintext: true,
        require_authentication: false,
        allow_legacy_unauthenticated: true,
        ..Default::default()
    }
}

include!("tests/basic.rs");
include!("tests/limits.rs");
include!("tests/guards.rs");
include!("tests/lifecycle.rs");
include!("tests/client_keepalive.rs");
