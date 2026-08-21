//! Node configuration management.
//!
//! Handles loading/saving node configuration including:
//! - Node identity (key pair, node ID)
//! - Network settings (virtual IP, MTU, CIDR)
//! - Control server endpoint
//! - Relay servers
//! - Port mappings

use serde::{de::Deserializer, Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

use crate::error::{DaemonError, Result};

include!("config/types.rs");
include!("config/persistence.rs");
include!("config/hostname.rs");
#[cfg(test)]
include!("config/tests.rs");
