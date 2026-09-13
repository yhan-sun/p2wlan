#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RoomDropReason {
    AuthorizationMissing,
    AuthorizationExpired,
    AuthorizationChanged,
    LocalIpMismatch,
    PeerMissing,
    PeerIpMismatch,
    UnknownVirtualIp,
    SourceNotLocal,
    OverlaySourceRejected,
    SourceNormalizationFailed,
    AclDenied,
    UnexpectedDestination,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoomPacketDrop {
    pub reason: String,
    pub direction: String,
    pub peer_id: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub age_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoomPeerTrafficDiagnostics {
    pub node_id: String,
    pub virtual_ip: String,
    pub tx_queued_packets: u64,
    pub rx_delivered_packets: u64,
    pub last_tx_age_ms: Option<u64>,
    pub last_rx_age_ms: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoomDataPlaneDiagnostics {
    pub authorization_state: String,
    pub local_ip: Option<String>,
    pub lease_remaining_ms: u64,
    pub drops: std::collections::BTreeMap<String, u64>,
    pub last_drop: Option<RoomPacketDrop>,
    pub peers: Vec<RoomPeerTrafficDiagnostics>,
}

#[derive(Debug, Default)]
struct RoomPeerTraffic {
    tx_queued_packets: u64,
    rx_delivered_packets: u64,
    last_tx: Option<Instant>,
    last_rx: Option<Instant>,
}

#[derive(Debug, Default)]
struct RoomTrafficLedger {
    drops: std::collections::BTreeMap<RoomDropReason, u64>,
    last_drop: Option<(Instant, RoomPacketDrop)>,
    peers: HashMap<String, RoomPeerTraffic>,
}

impl RoomDropReason {
    fn label(self) -> &'static str {
        match self {
            Self::AuthorizationMissing => "authorization_missing",
            Self::AuthorizationExpired => "authorization_expired",
            Self::AuthorizationChanged => "authorization_changed",
            Self::LocalIpMismatch => "local_ip_mismatch",
            Self::PeerMissing => "peer_missing",
            Self::PeerIpMismatch => "peer_ip_mismatch",
            Self::UnknownVirtualIp => "unknown_virtual_ip",
            Self::SourceNotLocal => "source_not_local",
            Self::OverlaySourceRejected => "overlay_source_rejected",
            Self::SourceNormalizationFailed => "source_normalization_failed",
            Self::AclDenied => "acl_denied",
            Self::UnexpectedDestination => "unexpected_destination",
        }
    }
}

impl RoomAuthorization {
    pub(crate) fn denial_reason(
        &self,
        peer_id: &str,
        peer_ip: &str,
        local_ip: &str,
    ) -> Option<RoomDropReason> {
        if !self.enabled {
            return None;
        }
        let Ok(snapshot) = self.snapshot.lock() else {
            return Some(RoomDropReason::AuthorizationMissing);
        };
        let Some(snapshot) = snapshot.as_ref() else {
            return Some(RoomDropReason::AuthorizationMissing);
        };
        if snapshot.expires_at <= Instant::now() || !snapshot.live.load(Ordering::Acquire) {
            return Some(RoomDropReason::AuthorizationExpired);
        }
        if snapshot.local_ip != local_ip {
            return Some(RoomDropReason::LocalIpMismatch);
        }
        match snapshot.peers.get(peer_id) {
            None => Some(RoomDropReason::PeerMissing),
            Some(ip) if ip != peer_ip => Some(RoomDropReason::PeerIpMismatch),
            _ => None,
        }
    }

    pub(crate) fn record_drop(
        &self,
        reason: RoomDropReason,
        direction: &str,
        peer_id: &str,
        source_ip: &str,
        destination_ip: &str,
    ) {
        if !self.enabled {
            return;
        }
        let Ok(mut ledger) = self.traffic.lock() else {
            return;
        };
        let emit = {
            let count = ledger.drops.entry(reason).or_default();
            *count = count.saturating_add(1);
            *count == 1
        };
        let now = Instant::now();
        let event = RoomPacketDrop {
            reason: reason.label().to_owned(),
            direction: direction.chars().take(8).collect(),
            peer_id: peer_id.chars().take(128).collect(),
            source_ip: source_ip.chars().take(64).collect(),
            destination_ip: destination_ip.chars().take(64).collect(),
            age_ms: 0,
        };
        if emit {
            tracing::debug!(
                event = "room_dataplane_drop",
                reason = reason.label(),
                direction = %event.direction,
                peer_id = %event.peer_id,
                source_ip = %event.source_ip,
                destination_ip = %event.destination_ip,
                "room packet rejected; counters are available in /status"
            );
        }
        ledger.last_drop = Some((now, event));
    }

    pub(crate) fn record_packet(&self, peer_id: &str, inbound: bool) {
        if !self.enabled {
            return;
        }
        let Ok(snapshot) = self.snapshot.lock() else {
            return;
        };
        let Some(_) = snapshot.as_ref().filter(|s| {
            s.expires_at > Instant::now()
                && s.live.load(Ordering::Acquire)
                && s.peers.contains_key(peer_id)
        }) else {
            return;
        };
        let Ok(mut ledger) = self.traffic.lock() else {
            return;
        };
        let peer = ledger.peers.entry(peer_id.to_owned()).or_default();
        if inbound {
            peer.rx_delivered_packets = peer.rx_delivered_packets.saturating_add(1);
            peer.last_rx = Some(Instant::now());
        } else {
            peer.tx_queued_packets = peer.tx_queued_packets.saturating_add(1);
            peer.last_tx = Some(Instant::now());
        }
    }

    pub fn diagnostics(&self, expected_local_ip: &str) -> Option<RoomDataPlaneDiagnostics> {
        if !self.enabled {
            return None;
        }
        let now = Instant::now();
        let age = |at: Instant| {
            now.saturating_duration_since(at)
                .as_millis()
                .min(u64::MAX as u128) as u64
        };
        let snapshot = self.snapshot.lock().ok();
        let snapshot = snapshot.as_deref().and_then(Option::as_ref);
        let state = match snapshot {
            None => "missing",
            Some(s) if s.expires_at <= now || !s.live.load(Ordering::Acquire) => "expired",
            Some(s) if s.local_ip != expected_local_ip => "local_ip_mismatch",
            Some(_) => "valid",
        };
        let ledger = self.traffic.lock().ok();
        let mut peers = snapshot
            .map(|s| {
                s.peers
                    .iter()
                    .map(|(id, ip)| {
                        let traffic = ledger.as_ref().and_then(|ledger| ledger.peers.get(id));
                        RoomPeerTrafficDiagnostics {
                            node_id: id.clone(),
                            virtual_ip: ip.clone(),
                            tx_queued_packets: traffic.map_or(0, |p| p.tx_queued_packets),
                            rx_delivered_packets: traffic.map_or(0, |p| p.rx_delivered_packets),
                            last_tx_age_ms: traffic.and_then(|p| p.last_tx).map(age),
                            last_rx_age_ms: traffic.and_then(|p| p.last_rx).map(age),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Some(RoomDataPlaneDiagnostics {
            authorization_state: state.to_owned(),
            local_ip: snapshot.map(|s| s.local_ip.clone()),
            lease_remaining_ms: snapshot.map_or(0, |s| {
                s.expires_at
                    .saturating_duration_since(now)
                    .as_millis()
                    .min(u64::MAX as u128) as u64
            }),
            drops: ledger
                .as_ref()
                .map(|l| {
                    l.drops
                        .iter()
                        .map(|(reason, count)| (reason.label().to_owned(), *count))
                        .collect()
                })
                .unwrap_or_default(),
            last_drop: ledger
                .as_ref()
                .and_then(|l| l.last_drop.as_ref())
                .map(|(at, event)| {
                    let mut event = event.clone();
                    event.age_ms = age(*at);
                    event
                }),
            peers,
        })
    }
}
