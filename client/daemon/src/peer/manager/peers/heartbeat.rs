impl PeerManager {
    /// Refresh only the canonical display timestamp of an unchanged online
    /// peer. This does not publish membership, routing, NAT or path evidence.
    /// Structural updates retain the original epoch-fenced transaction.
    fn try_refresh_peer_last_seen(&self, info: &PeerInfo) -> Option<PeerUpdate> {
        if !info.online {
            return None;
        }
        let endpoint = if info.endpoint.trim().is_empty() {
            None
        } else {
            Some(info.endpoint.parse::<SocketAddr>().ok()?)
        };
        let connections = self.connections.try_read().ok()?;
        let conn = connections.get(&info.node_id)?;
        let observed_last_seen = conn.last_seen.get();
        if !conn.online
            || conn.state == ConnectionState::Closed
            || info.last_seen <= observed_last_seen
            || conn.virtual_ip != info.virtual_ip
            || conn.public_key != info.public_key
            || conn.registration_seq != info.registration_seq
            || conn.capabilities != info.capabilities
            || conn.signaled_endpoint != endpoint
            || conn.device_name != info.device_name
            || conn.app_version != info.app_version
            || conn.nat_type != info.nat_type
            || conn.remote_relay_rtt_ms != info.relay_rtt_ms
            || conn.remote_nat_profile.is_none()
            || !conn.remote_nat_profile_matches_candidate_epoch()
        {
            return None;
        }
        let membership = self.peer_membership.try_lock().ok()?;
        let lifecycle = membership.active_generation(&info.node_id)?;
        let epoch = PathEpoch::new(
            self.current_network_generation_sync(),
            lifecycle,
            conn.remote_candidate_epoch(),
        );
        if conn.path_state_machine.current_epoch() != Some(epoch)
            || (self.config.relay.effective_path_policy(true)
                == crate::config::PathPolicy::DirectFirst
                && !conn.path_state_machine.direct_first_configured())
            || self.ip_to_node_snapshot.borrow().get(&info.virtual_ip) != Some(&info.node_id)
        {
            return None;
        }
        let identities = self.remote_identity_ledger.try_lock().ok()?;
        let identity = identities.get(&info.node_id)?;
        if identity.public_key != info.public_key
            || identity.registration_seq > info.registration_seq
        {
            return None;
        }
        // All fallible checks precede this sole advisory mutation. The
        // connection reader excludes removal/replacement; a concurrent network
        // generation change cannot turn this timestamp into an epoch fact.
        let previous_virtual_ip = (!conn.virtual_ip.is_empty()).then(|| conn.virtual_ip.clone());
        if !conn
            .last_seen
            .try_advance(observed_last_seen, info.last_seen)
        {
            return None;
        }
        Some(PeerUpdate {
            last_seen_only: true,
            previous_virtual_ip,
            ..PeerUpdate::default()
        })
    }
}
