use super::*;

impl WireGuardTransport {
    /// Encrypt and emit one packet while holding the peer's counter-ordering
    /// lock through the actual send. Synthetic confirmation packets use this
    /// path so a delayed low counter cannot fall behind a 64-packet burst.
    ///
    /// The lock wait is BOUNDED: if a burst of user traffic is holding the
    /// per-peer emit lock (encrypted_tx backpressure) the attempt is skipped
    /// and the caller's loop retries, so relay probes / direct-validation
    /// control packets are never blocked behind user traffic indefinitely.
    pub async fn encrypt_and_emit_outbound<F, Fut>(
        &self,
        packet: OutboundPacket,
        emit: F,
    ) -> Result<bool>
    where
        F: FnOnce(EncryptedPeerPacket) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        match self
            .encrypt_and_emit_outbound_with_lock_timeout(packet, CONTROL_EMIT_LOCK_TIMEOUT, emit)
            .await?
        {
            BoundedEmitOutcome::Sent => Ok(true),
            BoundedEmitOutcome::LockTimeout | BoundedEmitOutcome::SessionUnavailable => Ok(false),
        }
    }

    /// Encrypt and emit a synthetic packet with an explicit bounded wait for
    /// the per-peer counter-ordering lock. This keeps Direct validation from
    /// turning a busy live-TUN queue into a false high RTT while retaining the
    /// same FIFO/counter invariant as the ordinary control lane.
    pub(crate) async fn encrypt_and_emit_outbound_with_lock_timeout<F, Fut>(
        &self,
        packet: OutboundPacket,
        lock_timeout: Duration,
        emit: F,
    ) -> Result<BoundedEmitOutcome>
    where
        F: FnOnce(EncryptedPeerPacket) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        self.encrypt_and_emit_outbound_with_lock_timeout_typed(packet, lock_timeout, emit)
            .await
    }

    /// Typed-error variant used by DPLPMTUD so the final socket handoff can
    /// preserve `EMSGSIZE` without widening the ordinary control-send error
    /// surface.
    pub(crate) async fn encrypt_and_emit_outbound_with_lock_timeout_typed<F, Fut, E>(
        &self,
        packet: OutboundPacket,
        lock_timeout: Duration,
        emit: F,
    ) -> std::result::Result<BoundedEmitOutcome, E>
    where
        F: FnOnce(EncryptedPeerPacket) -> Fut,
        Fut: Future<Output = std::result::Result<(), E>>,
        E: From<DaemonError>,
    {
        let peer_id = packet.peer_id.clone();
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let lock_wait_started = Instant::now();
        let _emit_guard = match tokio::time::timeout(lock_timeout, emit_lock.lock()).await {
            Ok(guard) => guard,
            Err(_) => {
                debug!(
                    event = "control_emit_lock_timeout",
                    peer_id = %peer_id,
                    lock_timeout_ms = lock_timeout.as_millis() as u64,
                    lock_wait_ms = lock_wait_started.elapsed().as_millis() as u64,
                    bytes = packet.packet.len(),
                    "control/probe packet skipped: the outbound emit lock is held by busy user traffic; retrying on the next bounded tick"
                );
                return Ok(BoundedEmitOutcome::LockTimeout);
            }
        };
        debug!(
            event = "control_emit_lock_acquired",
            peer_id = %peer_id,
            lock_wait_ms = lock_wait_started.elapsed().as_millis() as u64,
            bytes = packet.packet.len(),
            "control/probe packet acquired the same per-peer counter-ordering lock as business traffic"
        );
        let packet_bytes = packet.packet.len();
        let Some(encrypted) = self.encrypt_outbound_inner(packet, false, false).await? else {
            return Ok(BoundedEmitOutcome::SessionUnavailable);
        };
        let counter = wire_counter(&encrypted.wire_bytes);
        let wire_fp = wire_fingerprint(&encrypted.wire_bytes);
        let encrypted_bytes = encrypted.wire_bytes.len();
        debug!(
            event = "control_transport_handoff_started",
            peer_id = %peer_id,
            counter = ?counter,
            bytes = encrypted_bytes,
            plaintext_bytes = packet_bytes,
            wire_fp = format_args!("{wire_fp:016x}"),
            "encrypted control packet entered its caller-provided transport handoff"
        );
        emit(encrypted).await?;
        debug!(
            event = "control_transport_handoff_completed",
            peer_id = %peer_id,
            counter = ?counter,
            bytes = encrypted_bytes,
            wire_fp = format_args!("{wire_fp:016x}"),
            "control packet handoff completed locally; peer delivery still requires its matching ACK"
        );
        Ok(BoundedEmitOutcome::Sent)
    }

    /// Encrypt one outbound packet.
    pub async fn encrypt_outbound(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        let emit_lock = self.outbound_emit_lock(&packet.peer_id).await;
        let _emit_guard = emit_lock.lock().await;
        self.encrypt_outbound_inner(packet, false, false).await
    }

    /// Encrypt one outbound user packet, or queue it briefly if the session is
    /// not installed yet. This is used only by the TUN data path; synthetic
    /// validation/probe packets continue to use encrypt_outbound so they do not
    /// fill the startup queue while polling for readiness.
    pub async fn encrypt_or_queue_outbound(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        let peer_id = packet.peer_id.clone();
        // Reserve the raw per-peer ingress turn before checking session state.
        // If a responder is being installed concurrently, the session-ready
        // flush and a live packet cannot cross each other at this boundary.
        let ingress_lock = self.outbound_ingress_lock(&peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let emit_guard = emit_lock.lock().await;
        let queued_packet = packet.clone();
        // Do not let this legacy convenience API create a second producer
        // ordering domain while the production network-outbound worker owns
        // plaintext parking. If the session is absent, park the raw packet in
        // the same transport backlog under the ingress guard below.
        let encrypted = self.encrypt_outbound_inner(packet, false, true).await?;
        drop(emit_guard);
        if encrypted.is_none() {
            self.queue_pending_outbound_locked(queued_packet, "session not ready")
                .await;
        }
        Ok(encrypted)
    }

    #[cfg(test)]
    /// Test-only compatibility wrapper that returns the guard with the
    /// encrypted packet for counter-ordering unit tests.
    pub(crate) async fn encrypt_outbound_with_guard(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<(EncryptedPeerPacket, Arc<OwnedMutexGuard<()>>)>> {
        let peer_id = packet.peer_id.clone();
        let emit_guard = Arc::new(self.acquire_outbound_emit_guard(&peer_id).await);
        let Some(encrypted) = self.encrypt_outbound_with_emit_guard(packet).await? else {
            return Ok(None);
        };
        Ok(Some((encrypted, emit_guard)))
    }

    /// Acquire the per-peer counter-ordering guard without doing any session
    /// work.  Callers that must compose this guard with another lifecycle
    /// transaction (for example the network-generation gate) acquire it
    /// first, so every production path uses the lock order
    /// `emit -> epoch -> sessions`.
    pub(crate) async fn acquire_outbound_emit_guard(&self, peer_id: &str) -> OwnedMutexGuard<()> {
        self.outbound_emit_lock(peer_id).await.lock_owned().await
    }

    /// Try to enter the per-peer counter-ordering boundary without waiting
    /// behind either the lock registry or business/control emission. Any
    /// contention is reported to the caller so it can retain exact work in
    /// its bounded ledger.
    pub(crate) fn try_acquire_outbound_emit_guard(
        &self,
        peer_id: &str,
    ) -> Option<OwnedMutexGuard<()>> {
        self.try_outbound_emit_lock(peer_id)?.try_lock_owned().ok()
    }

    /// Encrypt while the caller already owns the peer's emit guard.  Keeping
    /// this separate prevents a caller from taking the global epoch gate and
    /// then waiting for emit: inbound relay ACK/business evidence takes emit
    /// first and then commits generation-bound state, so the opposite order
    /// would create an ABBA deadlock.
    pub(crate) async fn encrypt_outbound_with_emit_guard(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        // The network-outbound actor owns the sole production plaintext FIFO.
        // Do not enter the legacy session backlog while holding emit_lock:
        // remove_session takes ingress_lock before emit_lock, so queueing
        // here would create an emit -> ingress wait against its ingress ->
        // emit teardown order.  Returning None lets the actor re-park the
        // plaintext without allocating a WireGuard counter.
        self.encrypt_outbound_inner(packet, false, true).await
    }

    /// Encrypt a business packet only if the cached active session instance
    /// is still installed.  The caller owns the per-peer emit guard and the
    /// network-epoch gate, so this method takes only the short sessions lock;
    /// it never performs network I/O while either ordering guard is held.
    pub(crate) async fn encrypt_outbound_with_emit_guard_for_session(
        &self,
        packet: OutboundPacket,
        expected_session_instance: u64,
    ) -> SessionBoundEncryption {
        let profiler = global_dataplane_profiler();
        let sampled = packet.trace.as_ref().map(|trace| trace.sampled);
        let session_lock_started = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let session_lock_acquired = Instant::now();
        let session_lock_wait_us = session_lock_acquired
            .duration_since(session_lock_started)
            .as_micros() as u64;
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_session_lock_wait_us",
                Duration::from_micros(session_lock_wait_us),
            );
        }
        let now = Instant::now();
        let Some(peer_sessions) = sessions.get_mut(&packet.peer_id) else {
            return SessionBoundEncryption::Unavailable {
                packet,
                reason: SessionUnavailableReason::PeerSessionsMissing,
            };
        };
        peer_sessions.prepare_active(now);
        let Some(active) = peer_sessions.active.as_mut() else {
            return SessionBoundEncryption::Unavailable {
                packet,
                reason: SessionUnavailableReason::ActiveMissing,
            };
        };
        if active.session_instance != expected_session_instance {
            return SessionBoundEncryption::Unavailable {
                packet,
                reason: SessionUnavailableReason::SessionInstanceMismatch,
            };
        }
        if active.session.is_expired() {
            return SessionBoundEncryption::Unavailable {
                packet,
                reason: SessionUnavailableReason::SessionExpired,
            };
        }

        let session_instance = active.session_instance;
        let crypto_started = Instant::now();
        let wire_bytes = match active.session.encrypt_to_bytes(&packet.packet) {
            Ok(wire_bytes) => wire_bytes,
            Err(error) => {
                return SessionBoundEncryption::Failed {
                    packet,
                    error: DaemonError::Peer(format!("WireGuard encrypt failed: {error}")),
                };
            }
        };
        let crypto_us = crypto_started.elapsed().as_micros() as u64;
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_crypto_exec_us",
                Duration::from_micros(crypto_us),
            );
        }
        debug!(
            event = "wireguard_outbound_counter_allocated",
            peer_id = %packet.peer_id,
            session_instance,
            counter = ?wire_counter(&wire_bytes),
            bytes = wire_bytes.len(),
            is_business = true,
            wire_fp = format_args!("{:016x}", wire_fingerprint(&wire_bytes)),
            "WireGuard counter allocated under the LAN Direct fast-path ordering lock"
        );
        let encrypted = EncryptedPeerPacket {
            room_authorization: packet.room_authorization,
            peer_id: packet.peer_id,
            dst_ip: packet.dst_ip,
            wire_bytes,
            is_business: true,
        };
        let session_lock_hold_us = session_lock_acquired.elapsed().as_micros() as u64;
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_session_lock_hold_us",
                Duration::from_micros(session_lock_hold_us),
            );
        }
        drop(sessions);
        SessionBoundEncryption::Encrypted {
            packet: encrypted,
            session_lock_wait_us,
            crypto_us,
        }
    }

    pub(in crate::transport) async fn outbound_emit_lock(&self, peer_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.outbound_emit_locks.lock().await;
        if let Some(lock) = locks.get(peer_id).and_then(Weak::upgrade) {
            return lock;
        }

        // A missing/dead target means this is a new lock incarnation. Prune
        // other dead weak entries at the same time so ongoing peer churn
        // cannot grow the registry without adding O(peer_count) work to every
        // ordinary packet on an already-active peer.
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(peer_id.to_string(), Arc::downgrade(&lock));
        lock
    }

    pub(in crate::transport) fn try_outbound_emit_lock(
        &self,
        peer_id: &str,
    ) -> Option<Arc<Mutex<()>>> {
        let mut locks = self.outbound_emit_locks.try_lock().ok()?;
        if let Some(lock) = locks.get(peer_id).and_then(Weak::upgrade) {
            return Some(lock);
        }

        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(peer_id.to_string(), Arc::downgrade(&lock));
        Some(lock)
    }

    pub(in crate::transport) async fn outbound_ingress_lock(
        &self,
        peer_id: &str,
    ) -> Arc<Mutex<()>> {
        let mut locks = self.outbound_ingress_locks.lock().await;
        if let Some(lock) = locks.get(peer_id).and_then(Weak::upgrade) {
            return lock;
        }

        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(peer_id.to_string(), Arc::downgrade(&lock));
        lock
    }

    pub(in crate::transport) async fn remove_idle_outbound_emit_lock(&self, peer_id: &str) {
        let mut locks = self.outbound_emit_locks.lock().await;
        if locks
            .get(peer_id)
            .is_some_and(|lock| lock.upgrade().is_none())
        {
            locks.remove(peer_id);
        }
    }

    pub(in crate::transport) async fn encrypt_outbound_inner(
        &self,
        packet: OutboundPacket,
        queue_if_unavailable: bool,
        is_business: bool,
    ) -> Result<Option<EncryptedPeerPacket>> {
        let profiler = global_dataplane_profiler();
        let sampled = packet.trace.as_ref().map(|trace| trace.sampled);
        let session_lock_started = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let session_lock_acquired = Instant::now();
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_session_lock_wait_us",
                session_lock_acquired.duration_since(session_lock_started),
            );
        }
        let now = Instant::now();
        let Some(peer_sessions) = sessions.get_mut(&packet.peer_id) else {
            drop(sessions);
            if queue_if_unavailable {
                self.queue_pending_outbound(packet, "session not ready")
                    .await;
            } else {
                debug!(
                    "No WireGuard session for peer {}; dropping {} byte packet",
                    packet.peer_id,
                    packet.packet.len()
                );
            }
            return Ok(None);
        };
        peer_sessions.prepare_active(now);
        let Some(active) = peer_sessions.active.as_mut() else {
            drop(sessions);
            if queue_if_unavailable {
                self.queue_pending_outbound(packet, "session expired before rekey")
                    .await;
            } else {
                debug!(
                    "No usable WireGuard session for peer {}; dropping {} byte packet until rekey completes",
                    packet.peer_id,
                    packet.packet.len()
                );
            }
            return Ok(None);
        };
        if active.session.is_expired() {
            drop(sessions);
            if queue_if_unavailable {
                self.queue_pending_outbound(packet, "session expired before rekey")
                    .await;
            } else {
                debug!(
                    "WireGuard session for peer {} expired; dropping {} byte packet until authenticated rekey confirmation",
                    packet.peer_id,
                    packet.packet.len()
                );
            }
            return Ok(None);
        }

        let session_instance = active.session_instance;
        let crypto_started = Instant::now();
        let wire_result = active.session.encrypt_to_bytes(&packet.packet);
        let crypto_us = crypto_started.elapsed().as_micros() as u64;
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_crypto_exec_us",
                Duration::from_micros(crypto_us),
            );
        }
        let wire_bytes =
            wire_result.map_err(|e| DaemonError::Peer(format!("WireGuard encrypt failed: {e}")))?;
        debug!(
            event = "wireguard_outbound_counter_allocated",
            peer_id = %packet.peer_id,
            session_instance,
            counter = ?wire_counter(&wire_bytes),
            bytes = wire_bytes.len(),
            is_business,
            wire_fp = format_args!("{:016x}", wire_fingerprint(&wire_bytes)),
            "WireGuard counter allocated under the per-peer emit ordering lock"
        );
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_session_lock_hold_us",
                session_lock_acquired.elapsed(),
            );
        }
        drop(sessions);

        Ok(Some(EncryptedPeerPacket {
            room_authorization: packet.room_authorization,
            peer_id: packet.peer_id,
            dst_ip: packet.dst_ip,
            wire_bytes,
            is_business,
        }))
    }

    pub(in crate::transport) async fn queue_pending_outbound(
        &self,
        packet: OutboundPacket,
        reason: &'static str,
    ) {
        let peer_id = packet.peer_id.clone();
        let ingress_lock = self.outbound_ingress_lock(&peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        self.queue_pending_outbound_locked(packet, reason).await;
    }

    /// Queue a raw packet while the caller owns the peer's ingress turn.
    /// Keeping the mutation and the flush/removal boundary under the same
    /// lock prevents a live producer from racing an in-flight session flush.
    pub(in crate::transport) async fn queue_pending_outbound_locked(
        &self,
        packet: OutboundPacket,
        reason: &'static str,
    ) {
        let now = Instant::now();
        let peer_id = packet.peer_id.clone();
        let packet_len = packet.packet.len();
        let (stale_dropped, stale_bytes, overflow_dropped, overflow_bytes, depth) = {
            let mut pending = self.pending_outbound.lock().await;
            let queue = pending.entry(peer_id.clone()).or_default();
            let stale_before = queue.len();
            let mut stale_bytes = 0usize;
            queue.retain(|queued| {
                let fresh = now.saturating_duration_since(queued.queued_at) <= PENDING_OUTBOUND_TTL;
                if !fresh {
                    stale_bytes = stale_bytes.saturating_add(queued.packet.packet.len());
                }
                fresh
            });
            let stale_dropped = stale_before.saturating_sub(queue.len());
            let mut overflow_dropped = 0usize;
            let mut overflow_bytes = 0usize;
            while queue.len() >= MAX_PENDING_OUTBOUND_PER_PEER {
                if let Some(old) = queue.pop_front() {
                    overflow_dropped = overflow_dropped.saturating_add(1);
                    overflow_bytes = overflow_bytes.saturating_add(old.packet.packet.len());
                }
            }
            queue.push_back(PendingOutboundPacket {
                queued_at: now,
                packet,
            });
            (
                stale_dropped,
                stale_bytes,
                overflow_dropped,
                overflow_bytes,
                queue.len(),
            )
        };
        if stale_dropped > 0 {
            self.record_outbound_drop(REASON_SESSION_QUEUE_STALE, stale_dropped, stale_bytes)
                .await;
            self.record_outbound_queue_event(
                "drop",
                &peer_id,
                REASON_SESSION_QUEUE_STALE,
                stale_dropped,
                stale_bytes,
            )
            .await;
        }
        if overflow_dropped > 0 {
            self.record_outbound_drop(REASON_SESSION_QUEUE_FULL, overflow_dropped, overflow_bytes)
                .await;
            self.record_outbound_queue_event(
                "drop",
                &peer_id,
                REASON_SESSION_QUEUE_FULL,
                overflow_dropped,
                overflow_bytes,
            )
            .await;
        }
        debug!(
            "Queued outbound packet for peer {} until WireGuard session is ready ({} bytes, reason={}, depth={}, stale_dropped={}, overflow_dropped={})",
            peer_id,
            packet_len,
            reason,
            depth,
            stale_dropped,
            overflow_dropped
        );
    }

    /// Forward a live raw TUN packet through the same per-peer ingress turn as
    /// session-ready backlog flushing. If a backlog exists, append behind it;
    /// otherwise hand the packet to the network-outbound worker immediately.
    pub(in crate::transport) async fn forward_raw_outbound(
        &self,
        mut packet: OutboundPacket,
    ) -> Result<()> {
        let peer_id = packet.peer_id.clone();
        let profiler = global_dataplane_profiler();
        let sampled = packet.trace.as_ref().map(|trace| trace.sampled);
        let ingress_wait_started = Instant::now();
        let ingress_lock = self.outbound_ingress_lock(&peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let ingress_guard_acquired = Instant::now();
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_outbound_ingress_lock_wait_us",
                ingress_wait_started.elapsed(),
            );
        }
        let pending_lock_started = Instant::now();
        let has_pending = self.pending_outbound.lock().await.contains_key(&peer_id);
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_pending_queue_lock_wait_us",
                pending_lock_started.elapsed(),
            );
        }
        if has_pending {
            self.queue_pending_outbound_locked(packet, "session backlog flush in progress")
                .await;
            if let Some(sampled) = sampled {
                profiler.record(
                    sampled,
                    "tx_outbound_ingress_lock_hold_us",
                    ingress_guard_acquired.elapsed(),
                );
            }
            return Ok(());
        }
        let queue_send_started = Instant::now();
        if let Some(trace) = packet.trace.as_mut() {
            trace.transport_queue_send_started = Some(queue_send_started);
        }
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record_value(
                trace.sampled,
                "tx_network_outbound_queue_depth_before_send",
                self.outbound_tx
                    .max_capacity()
                    .saturating_sub(self.outbound_tx.capacity()) as u64,
            );
        }
        let result = self
            .outbound_tx
            .send(packet)
            .await
            .map_err(|_| DaemonError::Network("outbound packet channel closed".to_string()));
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_outbound_ingress_lock_hold_us",
                ingress_guard_acquired.elapsed(),
            );
        }
        result
    }

    pub(crate) async fn flush_pending_outbound_for_peer(&self, peer_id: &str) {
        // Hold the ingress turn for the entire raw FIFO handoff. Live TUN
        // packets arriving during this operation either wait and follow the
        // flushed backlog, or are appended before this turn begins.
        let ingress_lock = self.outbound_ingress_lock(peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let now = Instant::now();
        let (packets, expired_count, expired_bytes) = {
            let mut pending = self.pending_outbound.lock().await;
            let Some(queue) = pending.get_mut(peer_id) else {
                return;
            };
            let mut packets = Vec::with_capacity(queue.len());
            let mut expired_count = 0usize;
            let mut expired_bytes = 0usize;
            while let Some(queued) = queue.pop_front() {
                if now.saturating_duration_since(queued.queued_at) <= PENDING_OUTBOUND_TTL {
                    packets.push(queued.packet);
                } else {
                    expired_count = expired_count.saturating_add(1);
                    expired_bytes = expired_bytes.saturating_add(queued.packet.packet.len());
                }
            }
            pending.remove(peer_id);
            (packets, expired_count, expired_bytes)
        };

        if expired_count > 0 {
            self.record_outbound_drop(REASON_SESSION_QUEUE_STALE, expired_count, expired_bytes)
                .await;
            self.record_outbound_queue_event(
                "drop",
                peer_id,
                REASON_SESSION_QUEUE_STALE,
                expired_count,
                expired_bytes,
            )
            .await;
            debug!(
                "Discarded {} expired pending outbound packets for peer {}",
                expired_count, peer_id
            );
        }
        if packets.is_empty() {
            return;
        }

        // Forward the RAW packets to the network outbound worker in FIFO
        // order.  The worker owns encryption: it holds the peer's emit lock
        // from encryption through the actual send, so counters are allocated
        // and transmitted strictly in queue order (never a relay probe /
        // direct-validation control packet jumping ahead of a queued business
        // packet's counter).
        let total_packets = packets.len();
        let total_bytes = packets
            .iter()
            .map(|packet| packet.packet.len())
            .sum::<usize>();
        let mut forwarded = 0usize;
        let mut forwarded_bytes = 0usize;
        for packet in packets {
            let packet_bytes = packet.packet.len();
            if let Err(err) = self.outbound_tx.send(packet).await {
                warn!(
                    "Pending outbound packet channel closed while flushing peer {}: {err}",
                    peer_id
                );
                let remaining = total_packets.saturating_sub(forwarded + 1);
                // The failed send owns the packet; count it and every item
                // still held locally instead of silently losing the session
                // queue during actor shutdown.
                self.record_outbound_drop(
                    REASON_SESSION_QUEUE_REMOVED,
                    remaining + 1,
                    total_bytes.saturating_sub(forwarded_bytes),
                )
                .await;
                self.record_outbound_queue_event(
                    "drop",
                    peer_id,
                    REASON_SESSION_QUEUE_REMOVED,
                    remaining + 1,
                    total_bytes.saturating_sub(forwarded_bytes),
                )
                .await;
                break;
            }
            forwarded = forwarded.saturating_add(1);
            forwarded_bytes = forwarded_bytes.saturating_add(packet_bytes);
        }
        debug!(
            "Forwarded pending outbound packets for peer {} (forwarded={}, expired={})",
            peer_id, forwarded, expired_count
        );
    }

    /// Forward routed packets from the dataplane to the network outbound
    /// worker WITHOUT encrypting them.
    ///
    /// The worker is the only place that encrypts business packets: it checks
    /// path usability first, parks PLAINTEXT packets for a not-yet-usable
    /// peer, and only then — once the path is confirmed — acquires the
    /// per-peer emit lock and encrypts + sends each packet in FIFO order
    /// holding the lock through the actual send.  A parked packet therefore
    /// never holds the emit lock, never occupies a WireGuard counter, and can
    /// never be overtaken on the wire by a higher-counter control packet.
    pub async fn run_outbound(
        &self,
        mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    ) -> Result<()> {
        while let Some(mut packet) = outbound_rx.recv().await {
            let profiler = global_dataplane_profiler();
            let transport_dequeued = Instant::now();
            if let Some(trace) = packet.trace.as_mut() {
                trace.transport_queue_dequeued = Some(transport_dequeued);
                profiler.record_value(
                    trace.sampled,
                    "tx_dataplane_queue_depth",
                    outbound_rx.len() as u64,
                );
                if let Some(enqueued) = trace.dataplane_queue_send_started {
                    profiler.record(
                        trace.sampled,
                        "tx_dataplane_queue_wait_us",
                        transport_dequeued.duration_since(enqueued),
                    );
                }
            }
            self.forward_raw_outbound(packet).await?;
        }
        Ok(())
    }
}
