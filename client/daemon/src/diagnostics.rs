//! Local diagnostics endpoint.
//!
//! This is intentionally tiny: a loopback HTTP listener that exposes runtime
//! status JSON without pulling in a web framework.

use std::sync::Arc;

use p2pnet_nat::NatProfile;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout, Duration};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::{DaemonError, Result};
use crate::gateway_mapping::GatewayMappingDiagnostics;
use crate::peer::{PeerDiagnostics, PeerManager, PeerManagerStats, DIRECT_RETRY_BASE_INTERVAL};
use crate::relay::{RelaySelectionDiagnostics, RelayTransport};
use crate::tasks::{HealthState, TaskManager};
use crate::traversal_history::TraversalHistoryDiagnostics;
use crate::udp::{UdpSocketPoolMemberDiagnostics, UdpTransport};

include!("diagnostics/types.rs");
include!("diagnostics/mtu.rs");
include!("diagnostics/server.rs");
include!("diagnostics/snapshot.rs");
include!("diagnostics/response.rs");
#[cfg(test)]
include!("diagnostics/tests.rs");
