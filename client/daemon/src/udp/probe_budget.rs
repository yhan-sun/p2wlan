//! Global outbound probe budget for UDP connectivity probes.
//!
//! Bounds how many punch/connectivity-check probes a single daemon may
//! emit per second, both in-memory (per network/peer/remote-IP) and with a
//! cross-process TSV file budget on the local filesystem. Split out of `udp.rs`.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p2pnet_crypto::hash as crypto_hash;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum OutboundProbeBudgetKey {
    Network,
    Peer(String),
    PeerRemoteIp(String, IpAddr),
}

pub(super) type OutboundProbeBudgetState =
    Arc<Mutex<HashMap<OutboundProbeBudgetKey, VecDeque<Instant>>>>;

#[derive(Debug, Clone)]
pub(super) struct GlobalOutboundProbeBudget {
    path: PathBuf,
}

impl GlobalOutboundProbeBudget {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(super) fn admit(
        &self,
        peer_id: &str,
        peer_addr: SocketAddr,
    ) -> std::io::Result<OutboundProbeAdmission> {
        let now_ms = unix_time_millis();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)?;
        lock_budget_file(&file)?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let mut entries = parse_global_probe_budget_entries(&contents, now_ms);
        let peer_key = global_probe_peer_key(peer_id);
        let remote_ip_key = global_probe_remote_ip_key(peer_id, peer_addr.ip());

        if entries.iter().filter(|(_, key)| key == "network").count()
            >= OUTBOUND_PROBE_BUDGET_PER_NETWORK
        {
            return Ok(OutboundProbeAdmission::GlobalNetworkRateLimited);
        }
        if entries.iter().filter(|(_, key)| key == &peer_key).count()
            >= OUTBOUND_PROBE_BUDGET_PER_PEER
        {
            return Ok(OutboundProbeAdmission::GlobalPeerRateLimited);
        }
        if entries
            .iter()
            .filter(|(_, key)| key == &remote_ip_key)
            .count()
            >= OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP
        {
            return Ok(OutboundProbeAdmission::GlobalRemoteIpRateLimited);
        }

        entries.push((now_ms, "network".to_string()));
        entries.push((now_ms, peer_key));
        entries.push((now_ms, remote_ip_key));
        write_global_probe_budget_entries(&mut file, &entries)?;
        unlock_budget_file(&file)?;
        Ok(OutboundProbeAdmission::Accepted)
    }
}

pub(super) const OUTBOUND_PROBE_BUDGET_WINDOW: Duration = Duration::from_secs(1);
pub(super) const OUTBOUND_PROBE_BUDGET_PER_NETWORK: usize = 768;
pub(super) const OUTBOUND_PROBE_BUDGET_PER_PEER: usize = 256;
// Symmetric NAT traversal often needs to sweep a short predicted port window
// against one public IP. Keep this bounded, but wide enough that the first
// synchronized punch is not cut off before the predicted window is covered.
pub(super) const OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP: usize = 192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutboundProbeAdmission {
    Accepted,
    NetworkRateLimited,
    PeerRateLimited,
    RemoteIpRateLimited,
    GlobalNetworkRateLimited,
    GlobalPeerRateLimited,
    GlobalRemoteIpRateLimited,
}

pub(super) fn default_global_outbound_probe_budget() -> Option<Arc<GlobalOutboundProbeBudget>> {
    if std::env::var("P2WLAN_DISABLE_GLOBAL_PROBE_BUDGET").as_deref() == Ok("1") {
        return None;
    }
    #[cfg(test)]
    {
        None
    }
    #[cfg(not(test))]
    {
        Some(Arc::new(GlobalOutboundProbeBudget::new(
            default_global_probe_budget_path(),
        )))
    }
}

#[cfg(not(test))]
fn default_global_probe_budget_path() -> PathBuf {
    std::env::var_os("P2WLAN_GLOBAL_PROBE_BUDGET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("p2wlan-outbound-probe-budget-v1.tsv"))
}

pub(super) fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn parse_global_probe_budget_entries(contents: &str, now_ms: u64) -> Vec<(u64, String)> {
    let window_ms = OUTBOUND_PROBE_BUDGET_WINDOW.as_millis() as u64;
    contents
        .lines()
        .filter_map(|line| {
            let (timestamp, key) = line.split_once('\t')?;
            let timestamp = timestamp.parse::<u64>().ok()?;
            (now_ms.saturating_sub(timestamp) < window_ms).then(|| (timestamp, key.to_string()))
        })
        .collect()
}

pub(super) fn write_global_probe_budget_entries(
    file: &mut File,
    entries: &[(u64, String)],
) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    for (timestamp, key) in entries {
        writeln!(file, "{timestamp}	{key}")?;
    }
    file.sync_data()?;
    Ok(())
}

fn global_probe_peer_key(peer_id: &str) -> String {
    format!("peer:{}", short_hash(peer_id.as_bytes()))
}

pub(super) fn global_probe_remote_ip_key(peer_id: &str, ip: IpAddr) -> String {
    format!("peer_remote_ip:{}:{ip}", short_hash(peer_id.as_bytes()))
}

fn short_hash(data: &[u8]) -> String {
    hex::encode(&crypto_hash(data)[..8])
}

#[cfg(unix)]
fn lock_budget_file(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_budget_file(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn lock_budget_file(_file: &File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn unlock_budget_file(_file: &File) -> std::io::Result<()> {
    Ok(())
}
