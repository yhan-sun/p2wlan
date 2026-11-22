use crate::NatProfile;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

/// Absence of a profile on the wire means the peer has not negotiated this protocol.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum NatKind {
    #[default]
    None,
    Cone,
    LinearSymmetric,
    RandomSymmetric,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PunchProfile {
    pub nat_type: NatKind,
    pub port_step: i32,
    pub port_hint: u16,
    pub upnp_mapped_addr: Option<SocketAddr>,
    pub tcp_candidates: Vec<SocketAddr>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tcp_simultaneous_open: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub udp_endpoint_receipts: bool,
    pub supports_sym_punch: bool,
}

impl PunchProfile {
    /// Observations are in send order on the primary socket. Repeated observations
    /// from a single server cannot establish how a mapping varies by destination.
    pub fn from_primary(profile: &NatProfile) -> Option<Self> {
        let local: SocketAddr = profile.local_addr.parse().ok()?;
        let mut servers = HashMap::new();
        let mut samples = Vec::new();
        let mut latest = None;
        let mut repeated_mapping_changed = false;
        for observation in &profile.observations {
            let Some(addr) = observation
                .mapped_address
                .as_deref()
                .and_then(|s| s.parse::<SocketAddr>().ok())
            else {
                continue;
            };
            if observation.failure_kind.is_none()
                && observation.error.is_none()
                && addr.is_ipv4() == local.is_ipv4()
                && addr.port() != 0
                && !addr.ip().is_unspecified()
                && !addr.ip().is_multicast()
            {
                latest = Some(addr);
                if let Some(previous) = servers.insert(observation.server.as_str(), addr) {
                    repeated_mapping_changed |= previous != addr;
                } else {
                    samples.push(addr);
                }
            }
        }
        let last = latest?;
        let same_ip = samples.iter().all(|addr| addr.ip() == last.ip());
        let same = samples.iter().all(|addr| *addr == last);
        let delta =
            |a: SocketAddr, b: SocketAddr| i32::from(b.port().wrapping_sub(a.port()) as i16);
        let step = samples
            .windows(2)
            .next()
            .map(|pair| delta(pair[0], pair[1]))
            .unwrap_or(0);
        let nat_type = if !repeated_mapping_changed && same && last == local {
            NatKind::None
        } else if !repeated_mapping_changed && same && samples.len() >= 2 {
            NatKind::Cone
        } else if !repeated_mapping_changed
            && same_ip
            && profile.confidence > 60
            && samples.len() >= 3
            && step != 0
            && samples.windows(2).all(|p| delta(p[0], p[1]) == step)
        {
            NatKind::LinearSymmetric
        } else {
            NatKind::RandomSymmetric
        };
        Some(Self {
            nat_type,
            port_step: if nat_type == NatKind::LinearSymmetric {
                step
            } else {
                0
            },
            port_hint: last.port(),
            supports_sym_punch: true,
            ..Self::default()
        })
    }

    pub fn advertisement(
        primary: Option<&NatProfile>,
        mapped: Option<SocketAddr>,
        supports_sym_punch: bool,
    ) -> Option<Self> {
        let mut profile = primary.and_then(Self::from_primary).or_else(|| {
            mapped.map(|address| Self {
                nat_type: NatKind::Cone,
                port_hint: address.port(),
                ..Self::default()
            })
        })?;
        profile.upnp_mapped_addr = mapped;
        profile.udp_endpoint_receipts = true;
        profile.supports_sym_punch = supports_sym_punch;
        profile.valid().then_some(profile)
    }

    /// A TCP listener can be offered even when UDP observation failed.
    pub fn tcp_only(&self) -> bool {
        self.nat_type == NatKind::None
            && self.port_hint == 0
            && !self.supports_sym_punch
            && self.upnp_mapped_addr.is_none()
            && !self.tcp_candidates.is_empty()
    }

    pub fn valid(&self) -> bool {
        let endpoint = |a: &SocketAddr| {
            a.port() != 0
                && !a.ip().is_unspecified()
                && !a.ip().is_multicast()
                && !matches!(a, SocketAddr::V6(v6) if v6.scope_id() != 0)
        };
        let correct_step = match self.nat_type {
            NatKind::LinearSymmetric => {
                self.port_hint != 0 && self.port_step != 0 && i16::try_from(self.port_step).is_ok()
            }
            _ => self.port_step == 0,
        };
        correct_step
            && (!self.tcp_simultaneous_open || !self.tcp_candidates.is_empty())
            && self.upnp_mapped_addr.as_ref().is_none_or(endpoint)
            && self.tcp_candidates.len() <= 16
            && self.tcp_candidates.iter().all(endpoint)
            && self.tcp_candidates.iter().collect::<HashSet<_>>().len() == self.tcp_candidates.len()
    }

    pub fn effective_kind(&self) -> NatKind {
        if self.upnp_mapped_addr.is_some() && self.nat_type != NatKind::None {
            NatKind::Cone
        } else {
            self.nat_type
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupPair {
    pub local_group: usize,
    pub remote_group: usize,
    pub mode: u8,
    pub role: u8,
}

/// Choose and break ties in the same peer-ID order on both ends. Mode is directional.
pub fn select_best_candidate_group_pair(
    local_id: &str,
    local: &[PunchProfile],
    remote_id: &str,
    remote: &[PunchProfile],
) -> Option<GroupPair> {
    if local_id == remote_id || local_id.is_empty() || remote_id.is_empty() {
        return None;
    }
    const MODES: [[u8; 4]; 4] = [[0, 0, 0, 0], [0, 1, 2, 4], [0, 3, 6, 7], [0, 5, 8, 9]];
    let role = u8::from(local_id > remote_id);
    local
        .iter()
        .enumerate()
        .filter(|(_, p)| p.valid())
        .flat_map(|(li, l)| {
            remote
                .iter()
                .enumerate()
                .filter(|(_, p)| p.valid())
                .map(move |(ri, r)| {
                    let mode = MODES[l.effective_kind() as usize][r.effective_kind() as usize];
                    let priority = match mode {
                        0 => 0,
                        1 => 1,
                        2 | 3 => 2,
                        4 | 5 => 3,
                        6 => 4,
                        7 | 8 => 5,
                        _ => 6,
                    };
                    let indices = if role == 0 { (li, ri) } else { (ri, li) };
                    (
                        (priority, indices),
                        GroupPair {
                            local_group: li,
                            remote_group: ri,
                            mode,
                            role,
                        },
                    )
                })
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, pair)| pair)
}
