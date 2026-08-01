//! IP packet parsing and inspection.
//!
//! Provides zero-copy parsing of IPv4 and IPv6 packets read from the
//! virtual interface. This is used for routing decisions, logging,
//! and protocol-level handling.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

include!("packet/protocol.rs");
include!("packet/ip.rs");
include!("packet/ipv4.rs");
include!("packet/ipv6.rs");
include!("packet/checksum.rs");
include!("packet/tests.rs");
