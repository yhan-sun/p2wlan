static NEXT_PEER_UPDATE_LOCK_ATTEMPT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

#[derive(Clone, Copy)]
enum PeerUpdateLockResource {
    NetworkEpochGate,
    ConnectionsWrite,
    IpToNodeWrite,
}

impl PeerUpdateLockResource {
    const ALL: [Self; 3] = [
        Self::NetworkEpochGate,
        Self::ConnectionsWrite,
        Self::IpToNodeWrite,
    ];

    const fn index(self) -> usize {
        match self {
            Self::NetworkEpochGate => 0,
            Self::ConnectionsWrite => 1,
            Self::IpToNodeWrite => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::NetworkEpochGate => "network_epoch_gate",
            Self::ConnectionsWrite => "connections_write",
            Self::IpToNodeWrite => "ip_to_node_write",
        }
    }
}

struct PeerUpdateLockTrace<'a> {
    manager: &'a PeerManager,
    context: String,
    wait_started: [Option<Instant>; 3],
    observed_contention: [bool; 3],
    held: [bool; 3],
}

impl<'a> PeerUpdateLockTrace<'a> {
    fn new(
        manager: &'a PeerManager,
        node_id: &str,
        network_generation: u64,
        peer_session_generation: Option<u64>,
        signal_context: Option<(&str, Option<u64>, &str)>,
    ) -> Self {
        let attempt =
            NEXT_PEER_UPDATE_LOCK_ATTEMPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let peer_fingerprint = crate::transport::wire_fingerprint(node_id.as_bytes());
        let (signal_fingerprint, signal_sequence, signal_type) = signal_context
            .map(|(signal_id, sequence, signal_type)| {
                (
                    format!(
                        "{:016x}",
                        crate::transport::wire_fingerprint(signal_id.as_bytes())
                    ),
                    sequence.map_or_else(|| "none".to_string(), |value| value.to_string()),
                    signal_type.to_string(),
                )
            })
            .unwrap_or_else(|| ("none".to_string(), "none".to_string(), "none".to_string()));
        Self {
            manager,
            context: format!(
                "attempt={attempt} peer_fp={peer_fingerprint:016x} network_generation={network_generation} peer_session_generation={} signal_fp={signal_fingerprint} signal_seq={signal_sequence} signal_type={signal_type}",
                peer_session_generation.map_or_else(|| "none".to_string(), |value| value.to_string())
            ),
            wait_started: [None; 3],
            observed_contention: [false; 3],
            held: [false; 3],
        }
    }

    fn wait_started(
        &mut self,
        resource: PeerUpdateLockResource,
        queue: &'static str,
        held: &'static str,
    ) {
        let index = resource.index();
        if self.wait_started[index].is_some() || self.observed_contention[index] {
            return;
        }
        self.wait_started[index] = Some(Instant::now());
        self.manager.emit_timeline(
            "peer_update_lock_wait_started",
            None,
            Some(resource.name()),
            Some(format!(
                "{} resource={} phase=waiting queue={} held={}",
                self.context,
                resource.name(),
                queue,
                held
            )),
        );
    }

    fn acquired(&mut self, resource: PeerUpdateLockResource) {
        let index = resource.index();
        self.held[index] = true;
        if let Some(started) = self.wait_started[index].take() {
            self.observed_contention[index] = true;
            self.manager.emit_timeline(
                "peer_update_lock_acquired",
                None,
                Some(resource.name()),
                Some(format!(
                    "{} resource={} phase=acquired wait_ms={}",
                    self.context,
                    resource.name(),
                    started.elapsed().as_millis()
                )),
            );
        }
    }

    fn queue_probe_acquired(&self, resource: PeerUpdateLockResource) {
        self.manager.emit_timeline(
            "peer_update_lock_queue_probe_acquired",
            None,
            Some(resource.name()),
            Some(format!(
                "{} resource={} phase=fair_writer_queue_probe_acquired",
                self.context,
                resource.name()
            )),
        );
    }

    fn queue_probe_released(&self, resource: PeerUpdateLockResource) {
        self.manager.emit_timeline(
            "peer_update_lock_queue_probe_released",
            None,
            Some(resource.name()),
            Some(format!(
                "{} resource={} phase=fair_writer_queue_probe_released",
                self.context,
                resource.name()
            )),
        );
    }

    fn released(&mut self, resource: PeerUpdateLockResource) {
        let index = resource.index();
        if !self.held[index] {
            return;
        }
        self.held[index] = false;
        if self.observed_contention[index] {
            self.manager.emit_timeline(
                "peer_update_lock_released",
                None,
                Some(resource.name()),
                Some(format!(
                    "{} resource={} phase=released",
                    self.context,
                    resource.name()
                )),
            );
        }
    }

    fn emit_peer_update_phase(&self, event: &'static str, phase: &'static str) {
        if !self
            .observed_contention
            .into_iter()
            .any(|observed| observed)
        {
            return;
        }
        self.manager.emit_timeline(
            event,
            None,
            None,
            Some(format!("{} phase={phase}", self.context)),
        );
    }
}

impl Drop for PeerUpdateLockTrace<'_> {
    fn drop(&mut self) {
        let held = PeerUpdateLockResource::ALL
            .into_iter()
            .filter(|resource| self.held[resource.index()])
            .map(PeerUpdateLockResource::name)
            .collect::<Vec<_>>()
            .join(",");
        for resource in PeerUpdateLockResource::ALL {
            let Some(started) = self.wait_started[resource.index()].take() else {
                continue;
            };
            self.manager.emit_timeline(
                "peer_update_lock_wait_cancelled",
                None,
                Some(resource.name()),
                Some(format!(
                    "{} resource={} phase=cancelled wait_ms={} held={}",
                    self.context,
                    resource.name(),
                    started.elapsed().as_millis(),
                    if held.is_empty() { "none" } else { &held }
                )),
            );
        }
    }
}

fn normalize_probe_session_id(session_id: Option<String>) -> Option<String> {
    session_id.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn prune_probe_session_bindings(conn: &mut PeerConnection, now: Instant) {
    conn.pending_probe_bindings
        .retain(|_, pending| pending.expires_at > now);
    if conn
        .previous_probe_binding
        .as_ref()
        .is_some_and(|previous| previous.expires_at <= now)
    {
        conn.previous_probe_binding = None;
    }
}

fn stage_probe_session_binding_on_connection(
    conn: &mut PeerConnection,
    token: String,
    session_id: Option<String>,
    ephemeral_shared: Option<[u8; 32]>,
    promote_on_match: bool,
) -> ProbeBindingStage {
    let now = Instant::now();
    prune_probe_session_bindings(conn, now);
    if conn.probe_binding_token.as_deref() == Some(token.as_str()) {
        return ProbeBindingStage::ReplayableDuplicate;
    }
    if let Some(pending) = conn.pending_probe_bindings.get_mut(&token) {
        // An exact cached answer replay gets a fresh delivery window.
        pending.expires_at = now + PENDING_PROBE_SESSION_BINDING_GRACE;
        return ProbeBindingStage::ReplayableDuplicate;
    }
    if conn
        .previous_probe_binding
        .as_ref()
        .and_then(|previous| previous.binding.token.as_deref())
        == Some(token.as_str())
    {
        return ProbeBindingStage::StaleDuplicate;
    }
    if conn.pending_probe_bindings.len() >= MAX_PENDING_PROBE_SESSION_BINDINGS_PER_PEER {
        return ProbeBindingStage::Busy;
    }
    conn.pending_probe_bindings.insert(
        token.clone(),
        PendingProbeSessionBinding {
            binding: ProbeSessionBinding {
                token: Some(token),
                session_id: normalize_probe_session_id(session_id),
                ephemeral_shared,
            },
            expires_at: now + PENDING_PROBE_SESSION_BINDING_GRACE,
            promote_on_match,
        },
    );
    ProbeBindingStage::Staged
}

fn install_active_probe_binding(
    conn: &mut PeerConnection,
    binding: ProbeSessionBinding,
    retain_previous: bool,
) -> bool {
    let previous = active_probe_binding(conn);
    let replaced = previous != binding;
    if retain_previous && replaced {
        conn.previous_probe_binding = Some(RetainedProbeSessionBinding {
            binding: previous,
            expires_at: Instant::now() + PROBE_SESSION_BINDING_OVERLAP,
        });
    } else if !retain_previous {
        conn.previous_probe_binding = None;
    }
    conn.probe_binding_token = binding.token.clone();
    conn.probe_session_id = binding.session_id.clone();
    conn.probe_ephemeral_shared = binding.ephemeral_shared;
    conn.pending_probe_bindings.clear();
    replaced
}

fn push_unique_probe_key(
    candidates: &mut Vec<ProbeKeyCandidate>,
    key: ProbeMacKey,
    role: ProbeKeyRole,
    session_id: Option<String>,
    session_generation: PeerSessionGeneration,
) {
    if !candidates.iter().any(|candidate| candidate.key == key) {
        candidates.push(ProbeKeyCandidate {
            key,
            role,
            session_generation,
            session_id,
        });
    }
}

fn push_probe_binding_compatibility_keys(
    candidates: &mut Vec<ProbeKeyCandidate>,
    base_key: ProbeMacKey,
    binding: &ProbeSessionBinding,
    session_generation: PeerSessionGeneration,
) {
    if let Some(session_id) = binding.session_id.as_deref() {
        push_unique_probe_key(
            candidates,
            derive_session_probe_mac_key(&base_key, session_id),
            ProbeKeyRole::Compatibility,
            binding.session_id.clone(),
            session_generation,
        );
    }
}

impl PeerManager {
    /// Set the explicit control-plane session ID used to bind Probe v2 MAC keys.
    pub async fn set_probe_session_id(&self, node_id: &str, session_id: Option<String>) -> bool {
        let normalized = normalize_probe_session_id(session_id);
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.pending_probe_bindings.clear();
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: None,
                session_id: normalized,
                ephemeral_shared: None,
            },
            false,
        );
        true
    }

    /// Set the explicit traversal session and optional ephemeral X25519 shared secret.
    pub async fn set_probe_session_binding(
        &self,
        node_id: &str,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
    ) -> bool {
        let normalized = normalize_probe_session_id(session_id);
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.pending_probe_bindings.clear();
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: None,
                session_id: normalized,
                ephemeral_shared,
            },
            false,
        );
        true
    }

    /// Stage a Probe-v2 replacement without changing the outbound key. A
    /// responder marks its staged key promotable by authenticated inbound
    /// traffic; an initiator waits for the matching answer and installs it
    /// explicitly.
    #[cfg(test)]
    pub(crate) async fn stage_probe_session_binding(
        &self,
        node_id: &str,
        token: String,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
        promote_on_match: bool,
    ) -> ProbeBindingStage {
        let token = token.trim().to_string();
        if token.is_empty() {
            return ProbeBindingStage::StaleDuplicate;
        }
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return ProbeBindingStage::PeerMissing;
        };
        stage_probe_session_binding_on_connection(
            conn,
            token,
            session_id,
            ephemeral_shared,
            promote_on_match,
        )
    }

    /// Try to stage a Probe-v2 replacement without waiting for the global
    /// connection writer. Callers that already own the canonical
    /// `emit -> network epoch` guards use this to avoid an ABBA cycle with a
    /// connection mutation that needs either outer guard before it can finish.
    /// `None` means only that the connection map is currently contended.
    pub(crate) fn try_stage_probe_session_binding(
        &self,
        node_id: &str,
        token: String,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
        promote_on_match: bool,
    ) -> Option<ProbeBindingStage> {
        let token = token.trim().to_string();
        if token.is_empty() {
            return Some(ProbeBindingStage::StaleDuplicate);
        }
        let mut conns = self.connections.try_write().ok()?;
        let Some(conn) = conns.get_mut(node_id) else {
            return Some(ProbeBindingStage::PeerMissing);
        };
        Some(stage_probe_session_binding_on_connection(
            conn,
            token,
            session_id,
            ephemeral_shared,
            promote_on_match,
        ))
    }

    /// Extend a staged responder binding after the control-plane answer
    /// delivery attempt completes. This keeps signaling latency separate from
    /// the authenticated adoption window.
    /// Refresh a responder binding without joining the connection writer
    /// queue.  The original staging grace remains valid on contention; later
    /// authenticated ingress is the authoritative promotion trigger.
    pub(crate) fn try_refresh_pending_probe_session_binding_grace(
        &self,
        node_id: &str,
        token: &str,
    ) -> PendingProbeBindingCommitOutcome {
        let Ok(mut conns) = self.connections.try_write() else {
            return PendingProbeBindingCommitOutcome::ContendedConnections;
        };
        let Some(conn) = conns.get_mut(node_id) else {
            return PendingProbeBindingCommitOutcome::Missing;
        };
        let Some(pending) = conn.pending_probe_bindings.get_mut(token) else {
            return if conn.probe_binding_token.as_deref() == Some(token) {
                PendingProbeBindingCommitOutcome::AlreadyCurrent
            } else {
                PendingProbeBindingCommitOutcome::Missing
            };
        };
        pending.expires_at = Instant::now() + PENDING_PROBE_SESSION_BINDING_GRACE;
        PendingProbeBindingCommitOutcome::Committed
    }

    /// Install an answer-confirmed Probe-v2 binding for outbound traffic while
    /// retaining the former inbound key during the overlap window.
    pub(crate) async fn install_probe_session_binding(
        &self,
        node_id: &str,
        token: String,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        prune_probe_session_bindings(conn, Instant::now());
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: Some(token),
                session_id: normalize_probe_session_id(session_id),
                ephemeral_shared,
            },
            true,
        );
        true
    }

    /// Roll back an unpublished Probe-v2 replacement. Returns false when the
    /// token was already promoted by authenticated traffic.
    pub(crate) async fn discard_pending_probe_session_binding(
        &self,
        node_id: &str,
        token: &str,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return true;
        };
        prune_probe_session_bindings(conn, Instant::now());
        if conn.probe_binding_token.as_deref() == Some(token) {
            return false;
        }
        conn.pending_probe_bindings.remove(token);
        true
    }

    /// Roll back an unpublished Probe-v2 replacement without entering the
    /// fair connection-writer queue. `None` means the caller must leave the
    /// exact token to its bounded TTL or retry the cleanup from an owning
    /// lifecycle worker; it must not turn cleanup into a global reader gate.
    pub(crate) fn try_discard_pending_probe_session_binding(
        &self,
        node_id: &str,
        token: &str,
    ) -> Option<bool> {
        let mut conns = self.connections.try_write().ok()?;
        let Some(conn) = conns.get_mut(node_id) else {
            return Some(true);
        };
        prune_probe_session_bindings(conn, Instant::now());
        if conn.probe_binding_token.as_deref() == Some(token) {
            return Some(false);
        }
        conn.pending_probe_bindings.remove(token);
        Some(true)
    }

    /// Promote a responder's staged Probe-v2 binding after a packet validates
    /// under that exact key and token.
    /// Promote the responder binding at an authenticated WireGuard boundary
    /// without parking the serial inbound actor behind a connection reader.
    /// On contention the promoted transport token remains in its bounded
    /// queue and the next authenticated packet retries the same transaction.
    pub(crate) fn try_confirm_pending_probe_session_binding(
        &self,
        node_id: &str,
        token: &str,
    ) -> PendingProbeBindingCommitOutcome {
        let Ok(mut conns) = self.connections.try_write() else {
            return PendingProbeBindingCommitOutcome::ContendedConnections;
        };
        let Some(conn) = conns.get_mut(node_id) else {
            return PendingProbeBindingCommitOutcome::Missing;
        };
        let should_promote = conn
            .pending_probe_bindings
            .get(token)
            .is_some_and(|pending| pending.promote_on_match);
        if !should_promote {
            return if conn.probe_binding_token.as_deref() == Some(token) {
                PendingProbeBindingCommitOutcome::AlreadyCurrent
            } else {
                PendingProbeBindingCommitOutcome::Missing
            };
        }
        let pending = conn
            .pending_probe_bindings
            .remove(token)
            .expect("pending Probe binding checked above");
        install_active_probe_binding(conn, pending.binding, true);
        PendingProbeBindingCommitOutcome::Committed
    }

    #[cfg(test)]
    pub(crate) async fn confirm_pending_probe_session_binding(
        &self,
        node_id: &str,
        token: &str,
    ) -> bool {
        matches!(
            self.try_confirm_pending_probe_session_binding(node_id, token),
            PendingProbeBindingCommitOutcome::Committed
                | PendingProbeBindingCommitOutcome::AlreadyCurrent
        )
    }

    /// Bridge a Probe-v2 adoption check with its matching WireGuard responder
    /// confirmation without holding the process-wide connection lock across
    /// an await.
    ///
    /// The UDP caller serializes this operation with the peer's adoption
    /// lifecycle lock.  The connection map is still re-checked after the
    /// transport await, so a peer removal, identity rotation, generation
    /// advance, or competing handshake commit cannot publish a stale Probe
    /// binding.  Keeping the map lock out of `confirm_transport` is important:
    /// WireGuard/session confirmation can wait on a slow transport, and a
    /// process-wide write lock there would block unrelated peer joins,
    /// control-signal consumption, and diagnostics snapshots.
    pub(crate) async fn confirm_probe_and_transport_transaction<F, Fut>(
        &self,
        node_id: &str,
        token: &str,
        confirm_transport: F,
    ) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let expected = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            prune_probe_session_bindings(conn, Instant::now());
            let should_promote = conn
                .pending_probe_bindings
                .get(token)
                .is_some_and(|pending| pending.promote_on_match);
            let already_active = conn.probe_binding_token.as_deref() == Some(token);
            if !should_promote && !already_active {
                return false;
            }
            (should_promote, already_active)
        };

        if !confirm_transport().await {
            return false;
        }

        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        prune_probe_session_bindings(conn, Instant::now());

        // A transport confirmation may complete after the peer was removed or
        // its binding was replaced.  In that case the transport result is
        // terminal for this transaction; never install the old counter/key
        // into the new connection generation.
        if conn.probe_binding_token.as_deref() == Some(token) {
            return true;
        }
        if !expected.0 || expected.1 {
            return false;
        }
        let Some(pending) = conn.pending_probe_bindings.remove(token) else {
            return false;
        };
        if !pending.promote_on_match {
            return false;
        }
        install_active_probe_binding(conn, pending.binding, true);
        true
    }

    /// Return the Probe v2 MAC key for a known peer, if both public keys are valid.
    ///
    /// New peers with an explicit signaling session ID receive a session-bound
    /// key; legacy peers without a session ID retain the static v2 skeleton key.
    pub async fn probe_key_for_peer(&self, node_id: &str) -> Option<ProbeMacKey> {
        self.probe_key_and_session_for_peer(node_id)
            .await
            .map(|(key, _)| key)
    }

    /// Return the active Probe v2 MAC key together with the session that
    /// derived it under one connection snapshot.  The session is carried by a
    /// pending outbound probe solely for diagnostics attribution; it is never
    /// trusted in place of MAC verification.
    pub(crate) async fn probe_key_and_session_for_peer(
        &self,
        node_id: &str,
    ) -> Option<(ProbeMacKey, Option<String>)> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|connection| {
                effective_probe_mac_key(connection)
                    .map(|key| (key, connection.probe_session_id.clone()))
            })
    }

    /// Snapshot the active Probe session for peer-scoped receive diagnostics.
    /// The value is not sent on the wire and cannot influence authentication.
    pub(crate) async fn probe_session_id_for_peer(&self, node_id: &str) -> Option<String> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|connection| connection.probe_session_id.clone())
    }

    /// Return role-tagged Probe-v2 keys for inbound authentication. Only an
    /// exact match on a promotable pending key can commit a responder rekey.
    pub(crate) async fn probe_key_candidates_for_peer(
        &self,
        node_id: &str,
    ) -> Vec<ProbeKeyCandidate> {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return Vec::new();
        };
        if !conn.online {
            return Vec::new();
        }
        let Some(session_generation) = self
            .peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_generation(node_id)
        else {
            return Vec::new();
        };
        prune_probe_session_bindings(conn, Instant::now());
        let Some(base_key) = conn.probe_mac_key else {
            return Vec::new();
        };

        let active = active_probe_binding(conn);
        let pending = conn.pending_probe_bindings.clone();
        let previous = conn.previous_probe_binding.clone();
        let mut candidates = Vec::new();
        push_unique_probe_key(
            &mut candidates,
            probe_mac_key_for_binding(base_key, &active),
            ProbeKeyRole::Active,
            active.session_id.clone(),
            session_generation,
        );
        for pending in pending.values() {
            let role = if pending.promote_on_match {
                ProbeKeyRole::Pending {
                    token: pending
                        .binding
                        .token
                        .clone()
                        .expect("staged Probe binding must have a token"),
                }
            } else {
                ProbeKeyRole::Compatibility
            };
            push_unique_probe_key(
                &mut candidates,
                probe_mac_key_for_binding(base_key, &pending.binding),
                role,
                pending.binding.session_id.clone(),
                session_generation,
            );
        }
        if let Some(previous) = previous.as_ref() {
            push_unique_probe_key(
                &mut candidates,
                probe_mac_key_for_binding(base_key, &previous.binding),
                ProbeKeyRole::Previous,
                previous.binding.session_id.clone(),
                session_generation,
            );
        }
        push_probe_binding_compatibility_keys(
            &mut candidates,
            base_key,
            &active,
            session_generation,
        );
        for pending in pending.values() {
            push_probe_binding_compatibility_keys(
                &mut candidates,
                base_key,
                &pending.binding,
                session_generation,
            );
        }
        if let Some(previous) = previous.as_ref() {
            push_probe_binding_compatibility_keys(
                &mut candidates,
                base_key,
                &previous.binding,
                session_generation,
            );
        }
        push_unique_probe_key(
            &mut candidates,
            base_key,
            ProbeKeyRole::Compatibility,
            None,
            session_generation,
        );
        candidates
    }

    /// Return Probe v2 MAC keys to try for inbound compatibility.
    ///
    /// The strongest key is first.  When a session ID is active, weaker
    /// session/static fallbacks are retained so upgraded peers can still receive
    /// probes from older clients or from signals relayed by older control servers.
    pub async fn probe_keys_for_peer(&self, node_id: &str) -> Vec<ProbeMacKey> {
        self.probe_key_candidates_for_peer(node_id)
            .await
            .into_iter()
            .map(|candidate| candidate.key)
            .collect()
    }
}
