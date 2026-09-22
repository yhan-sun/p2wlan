impl PeerManager {
    /// Record a direct traversal timeline event for diagnostics.
    pub async fn record_direct_event(
        &self,
        node_id: &str,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        // Ordinary diagnostics must never become a back-pressure point for the
        // control event loop. A direct probe, candidate handover or relay
        // renewal may briefly own the connection map while it commits state;
        // the typed timeline event below remains authoritative when that map
        // is contended. Hard↔Hard terminal markers remain durable, while the
        // pre-send sweep marker is intentionally best-effort so it cannot
        // delay the first UDP datagram.
        let generation = self.current_network_generation_sync();
        let stage = stage.into();
        let detail = detail.into();
        if !Self::direct_event_requires_durable_ring(&stage) {
            self.record_direct_event_non_queuing(
                node_id,
                stage,
                endpoint,
                candidate_count,
                sent_probes,
                detail,
            );
            return;
        }
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.get_mut(node_id) {
            conn.record_direct_event(
                generation,
                stage.clone(),
                endpoint,
                candidate_count,
                sent_probes,
                detail.clone(),
            );
        }
        self.emit_direct_traversal_debug(
            node_id,
            generation,
            &stage,
            endpoint,
            None,
            candidate_count,
            sent_probes,
            &detail,
        );
    }

    /// Best-effort diagnostic event for serial actor paths. This method never
    /// joins the fair connection-writer queue; the structured debug timeline
    /// is still emitted when the in-memory per-peer ring is contended.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_direct_event_non_queuing(
        &self,
        node_id: &str,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let generation = self.current_network_generation_sync();
        let stage = stage.into();
        let detail = detail.into();
        if let Ok(mut connections) = self.connections.try_write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event(
                    generation,
                    stage.clone(),
                    endpoint,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        }
        self.emit_direct_traversal_debug(
            node_id,
            generation,
            &stage,
            endpoint,
            None,
            candidate_count,
            sent_probes,
            &detail,
        );
    }

    /// Generation-stable direct-event recorder with the actual UDP socket
    /// index when receive-side code can identify it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_event_for_generation_with_socket(
        &self,
        node_id: &str,
        generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let stage = stage.into();
        let detail = detail.into();
        if Self::direct_event_requires_durable_ring(&stage) {
            let mut connections = self.connections.write().await;
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event_with_socket(
                    generation,
                    stage.clone(),
                    endpoint,
                    socket_index,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        } else if let Ok(mut connections) = self.connections.try_write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event_with_socket(
                    generation,
                    stage.clone(),
                    endpoint,
                    socket_index,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        }
        self.emit_direct_traversal_debug(
            node_id,
            generation,
            &stage,
            endpoint,
            socket_index,
            candidate_count,
            sent_probes,
            &detail,
        );
    }

    /// Hard↔Hard winner and terminal markers are acceptance evidence, not
    /// best-effort trace noise. Wait for the connection writer for these
    /// bounded events so reciprocal validation cannot silently drop the
    /// selected-socket or final summary/failure evidence.
    /// `hard_hard_sweep_started` and
    /// `hard_hard_direct_validation_started` are deliberately excluded: both
    /// run on the punch-at/confirmation timing path and must not hold the
    /// first UDP send or confirmation grace behind the connection writer.
    fn direct_event_requires_durable_ring(stage: &str) -> bool {
        matches!(
            stage,
            "hard_hard_probe_summary"
                | "hard_hard_birthday_sweep_summary"
                | "hard_hard_attempt_report"
                | "hard_hard_sweep_completed"
                | "hard_hard_sweep_failed"
                | "hard_hard_failed"
                | "hard_hard_winner_selected"
        )
    }

    /// Commit one endpoint-free Hard↔Hard attempt report to the existing
    /// bounded per-peer diagnostics ring. Every identity is rechecked before
    /// the write so a late old attempt is never attributed to a replacement
    /// peer session or candidate epoch. The report is not consulted by any
    /// production decision.
    pub(crate) async fn record_hard_hard_attempt_report(
        &self,
        peer_id: &str,
        session_token: &str,
        report: HardHardAttemptReport,
    ) -> bool {
        if self.current_network_generation_sync() != report.network_generation
            || !self.peer_session_is_current_sync(
                peer_id,
                PeerSessionGeneration(report.peer_session_generation),
            )
            || self.current_remote_candidate_epoch(peer_id).await != Some(report.remote_candidate_epoch)
        {
            self.emit_timeline_debug(
                "hard_hard_attempt_report_fenced",
                Some("direct"),
                Some("stale_attempt_identity"),
                Some(format!(
                    "peer_id={peer_id} generation={} session_tag={} failure_class={}",
                    report.network_generation, report.session_tag, report.failure_class,
                )),
            );
            return false;
        }
        let Some(socket_index) = report.socket_index else {
            return false;
        };
        let session_is_current = self
            .hard_hard_attempt_report_identity_is_current(
                peer_id,
                session_token,
                report.network_generation,
                report.remote_candidate_epoch,
                report.punch_generation,
                socket_index,
                report.attempt,
            )
            .await;
        if !session_is_current {
            return false;
        }
        let detail = format!(
            "peer_id={peer_id} generation={} session_tag={} role={} mode={} attempt={} failure_class={} terminal_reason={} physical_datagrams_sent={} send_errors={} budget_skipped={}",
            report.network_generation,
            report.session_tag,
            report.role,
            report.mode,
            report.attempt,
            report.failure_class,
            report.terminal_reason,
            report.counts.send_success_datagrams,
            report.counts.send_errors,
            report.counts.budget_skipped,
        );
        let mut connections = self.connections.write().await;
        let Some(connection) = connections.get_mut(peer_id) else {
            return false;
        };
        if !self.peer_session_is_current_sync(
            peer_id,
            PeerSessionGeneration(report.peer_session_generation),
        ) || connection.remote_candidate_epoch() != report.remote_candidate_epoch
        {
            return false;
        }
        tracing::info!(
            event = "hard_hard_attempt_report",
            peer_id,
            network_generation = report.network_generation,
            session_tag = %report.session_tag,
            role = %report.role,
            mode = %report.mode,
            attempt = report.attempt,
            failure_class = %report.failure_class,
            terminal_reason = %report.terminal_reason,
            direct_confirmed = report.direct_confirmed,
            "hard_hard_attempt_report"
        );
        connection.record_hard_hard_attempt_report(report, detail);
        true
    }

    /// Record a typed failure that terminated before the short-lived session
    /// ledger owned a dynamic socket. The report is checked directly against
    /// the current network/session/candidate/profile identities, including
    /// paths where the strategy planner itself was temporarily unavailable;
    /// a replacement lifecycle can never inherit this observation. This
    /// remains diagnostics-only.
    pub(crate) async fn record_hard_hard_pre_session_attempt_report(
        &self,
        peer_id: &str,
        report: HardHardAttemptReport,
    ) -> bool {
        if report.socket_index.is_some()
            || self.current_network_generation_sync() != report.network_generation
            || !self.peer_session_is_current_sync(
                peer_id,
                PeerSessionGeneration(report.peer_session_generation),
            )
        {
            return false;
        }
        let detail = format!(
            "peer_id={peer_id} generation={} session_tag={} role={} mode={} attempt={} failure_class={} terminal_reason={} pre_session=true",
            report.network_generation,
            report.session_tag,
            report.role,
            report.mode,
            report.attempt,
            report.failure_class,
            report.terminal_reason,
        );
        let mut connections = self.connections.write().await;
        let Some(connection) = connections.get_mut(peer_id) else {
            return false;
        };
        if self.current_network_generation_sync() != report.network_generation
            || !self.peer_session_is_current_sync(
                peer_id,
                PeerSessionGeneration(report.peer_session_generation),
            )
            || connection.remote_candidate_epoch() != report.remote_candidate_epoch
            || self.current_local_profile_generation_sync() != report.local_profile_generation
            || !connection.online
            || connection.state == ConnectionState::Direct
            || !connection.remote_nat_profile_is_fresh()
            || !connection.remote_nat_profile_matches_candidate_epoch()
            || connection
                .remote_nat_profile
                .as_ref()
                .and_then(|profile| profile.generation)
                != Some(report.remote_profile_generation)
        {
            return false;
        }
        tracing::info!(
            event = "hard_hard_attempt_report",
            peer_id,
            network_generation = report.network_generation,
            session_tag = %report.session_tag,
            role = %report.role,
            mode = %report.mode,
            attempt = report.attempt,
            failure_class = %report.failure_class,
            terminal_reason = %report.terminal_reason,
            direct_confirmed = report.direct_confirmed,
            pre_session = true,
            "hard_hard_attempt_report"
        );
        connection.record_hard_hard_attempt_report(report, detail);
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_direct_traversal_debug(
        &self,
        node_id: &str,
        generation: u64,
        stage: &str,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: &str,
    ) {
        let Some(event) = direct_traversal_timeline_event(stage) else {
            return;
        };
        let reason_code = detail
            .split_whitespace()
            .find_map(|part| part.strip_prefix("reason_code="))
            .filter(|value| !value.is_empty())
            .or_else(|| direct_traversal_default_reason(stage));
        self.emit_timeline_debug(
            event,
            Some("direct"),
            reason_code,
            Some(format_direct_traversal_timeline_detail(
                node_id,
                generation,
                stage,
                endpoint,
                socket_index,
                candidate_count,
                sent_probes,
                detail,
            )),
        );
    }

    /// Record a lifecycle event for one owned encrypted direct-validation
    /// worker.  The worker's lease supplies `generation` and
    /// `validation_session_id`; do not substitute the manager's current
    /// generation here because this method is also used to explain a worker
    /// that was cancelled by a generation advance.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event(
        &self,
        node_id: &str,
        generation: u64,
        validation_session_id: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.record_direct_validation_event_with_socket(
            node_id,
            generation,
            validation_session_id,
            stage,
            endpoint,
            None,
            candidate_count,
            sent_probes,
            detail,
        )
        .await;
    }

    /// Generation- and owner-stable validation lifecycle recorder with the
    /// actual UDP socket index where it is available.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event_with_socket(
        &self,
        node_id: &str,
        generation: u64,
        validation_session_id: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.record_direct_validation_event_with_metadata(
            node_id,
            generation,
            DirectValidationEventMetadata {
                local_validation_session_id: Some(validation_session_id),
                ..DirectValidationEventMetadata::default()
            },
            stage,
            endpoint,
            socket_index,
            candidate_count,
            sent_probes,
            detail,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event_with_metadata(
        &self,
        node_id: &str,
        generation: u64,
        metadata: DirectValidationEventMetadata,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let stage = stage.into();
        let detail = detail.into();
        if let Ok(mut connections) = self.connections.try_write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_validation_event_with_metadata(
                    generation,
                    metadata,
                    stage.clone(),
                    endpoint,
                    socket_index,
                    candidate_count,
                    sent_probes,
                    detail.clone(),
                );
            }
        }

        // The `/status` direct-event ring already has the full typed record,
        // but it is only collected after a round.  Mirror the lifecycle into
        // the process timeline at DEBUG level so a live failure can be
        // diagnosed from one log stream with the same corr_id/t_ms as relay,
        // WireGuard and generation events.  Do not copy validation owner
        // tokens from the legacy detail strings into this log line.
        if let Some(event) = direct_validation_timeline_event(&stage) {
            let reason_code = detail
                .split_whitespace()
                .find_map(|part| part.strip_prefix("reason_code="))
                .filter(|value| !value.is_empty())
                .or_else(|| direct_validation_default_reason(&stage));
            let timeline_detail = format_direct_validation_timeline_detail(
                node_id,
                generation,
                &stage,
                endpoint,
                socket_index,
                candidate_count,
                sent_probes,
                metadata,
                &detail,
            );
            self.emit_timeline_debug(event, Some("direct"), reason_code, Some(timeline_detail));
        }
    }

    /// Record a direct traversal event with structured probe coverage counters.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_direct_event_with_probe_coverage(
        &self,
        node_id: &str,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
        socket0_count: u32,
        alt_socket_count: u32,
        unique_target_ports: u32,
        repeated_target_ports: u32,
    ) {
        let generation = self.current_network_generation_sync();
        if let Ok(mut connections) = self.connections.try_write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.record_direct_event_with_probe_coverage(
                    generation,
                    stage,
                    endpoint,
                    candidate_count,
                    sent_probes,
                    detail,
                    socket0_count,
                    alt_socket_count,
                    unique_target_ports,
                    repeated_target_ports,
                );
            }
        }
    }
}

/// Stages that are useful in the live, correlation-id based timeline.  The
/// high-volume candidate/scatter events remain in the bounded `/status` ring;
/// these are the owned request/ACK lifecycle boundaries needed to explain a
/// Direct success, timeout, cancellation, or stale ACK from a daemon log.
fn direct_validation_timeline_event(stage: &str) -> Option<&'static str> {
    match stage {
        "direct_validation_queued" => Some("direct_validation_queued"),
        "direct_validation_dropped" => Some("direct_validation_dropped"),
        "direct_validation_started" => Some("direct_validation_started"),
        "direct_validation_waiting_for_session" => Some("direct_validation_waiting_for_session"),
        "direct_validation_session_ready" => Some("direct_validation_session_ready"),
        "direct_validation_request_prepared" => Some("direct_validation_request_prepared"),
        "direct_validation_request_sent" => Some("direct_validation_request_sent"),
        "direct_validation_request_received" => Some("direct_validation_request_received"),
        "direct_validation_request_dropped" => Some("direct_validation_request_dropped"),
        "direct_validation_ack_sent" => Some("direct_validation_ack_sent"),
        "direct_validation_ack_received" => Some("direct_validation_ack_received"),
        "direct_validation_ack_wait_timeout" => Some("direct_validation_ack_wait_timeout"),
        "direct_validation_ack_unmatched" => Some("direct_validation_ack_unmatched"),
        "direct_validation_ack_not_promoted" => Some("direct_validation_ack_not_promoted"),
        "direct_validation_ack_send_failed" => Some("direct_validation_ack_send_failed"),
        "direct_validation_emit_lock_timeout" => Some("direct_validation_emit_lock_timeout"),
        "direct_validation_timed_out" => Some("direct_validation_timed_out"),
        "direct_validation_failed" => Some("direct_validation_failed"),
        "direct_validation_cancelled" => Some("direct_validation_cancelled"),
        "direct_validation_completed" => Some("direct_validation_completed"),
        "direct_validation_promoted" => Some("direct_validation_promoted"),
        "direct_validation_suppressed" => Some("direct_validation_suppressed"),
        "direct_validation_slow_relay_retained" => Some("direct_validation_slow_relay_retained"),
        "direct_path_promoted" => Some("direct_path_promoted"),
        _ => None,
    }
}

fn direct_validation_default_reason(stage: &str) -> Option<&'static str> {
    match stage {
        "direct_validation_timed_out" => Some("direct_validation_timeout"),
        "direct_validation_failed" => Some("direct_validation_send_failed"),
        "direct_validation_cancelled" => Some("direct_validation_cancelled"),
        "direct_validation_ack_unmatched" => Some("direct_validation_ack_unmatched"),
        "direct_validation_ack_wait_timeout" => Some("direct_validation_ack_timeout"),
        "direct_validation_ack_send_failed" => Some("direct_validation_ack_send_failed"),
        "direct_validation_emit_lock_timeout" => Some("direct_validation_emit_lock_timeout"),
        "direct_validation_dropped" => Some("direct_validation_queue_dropped"),
        "direct_validation_request_dropped" => Some("direct_validation_request_dropped"),
        "direct_validation_ack_not_promoted" => Some("direct_validation_promotion_rejected"),
        "direct_validation_suppressed" => Some("direct_validation_suppressed"),
        _ => None,
    }
}

fn direct_traversal_timeline_event(stage: &str) -> Option<&'static str> {
    match stage {
        "direct_punch_started" => Some("direct_punch_started"),
        "direct_punch_completed" => Some("direct_punch_completed"),
        "direct_punch_failed" => Some("direct_punch_failed"),
        "direct_punch_cancelled" => Some("direct_punch_cancelled"),
        "direct_fast_probe_started" => Some("direct_fast_probe_started"),
        "direct_fast_probe_sent" => Some("direct_fast_probe_sent"),
        "direct_fast_probe_failed" => Some("direct_fast_probe_failed"),
        "direct_fast_probe_confirmed" => Some("direct_fast_probe_confirmed"),
        "direct_probe_ack_timeout" => Some("direct_probe_ack_timeout"),
        "direct_probe_budget_exhausted" => Some("direct_probe_budget_exhausted"),
        "direct_candidates_ready" => Some("direct_candidates_ready"),
        "candidate_pair_probe_succeeded" => Some("candidate_pair_probe_succeeded"),
        "retry_punch_started" => Some("retry_punch_started"),
        "retry_probes_sent" => Some("retry_probes_sent"),
        "retry_ack_timeout" => Some("retry_ack_timeout"),
        "retry_probe_succeeded" => Some("retry_probe_succeeded"),
        "retry_send_error" => Some("retry_send_error"),
        "direct_reclaim_punch_started" => Some("direct_reclaim_punch_started"),
        "direct_reclaim_probes_sent" => Some("direct_reclaim_probes_sent"),
        "direct_reclaim_ack_timeout" => Some("direct_reclaim_ack_timeout"),
        "direct_reclaim_probe_succeeded" => Some("direct_reclaim_probe_succeeded"),
        "direct_reclaim_send_error" => Some("direct_reclaim_send_error"),
        "fresh_mapping_generation_started" => Some("fresh_mapping_generation_started"),
        "fresh_mapping_generation_completed" => Some("fresh_mapping_generation_completed"),
        "fresh_mapping_generation_failed" => Some("fresh_mapping_generation_failed"),
        "fresh_mapping_prediction_signaled" => Some("fresh_mapping_prediction_signaled"),
        "direct_validation_observation_merged" => Some("direct_validation_observation_merged"),
        "direct_validation_suppressed" => Some("direct_validation_suppressed"),
        _ => None,
    }
}

fn direct_traversal_default_reason(stage: &str) -> Option<&'static str> {
    match stage {
        "direct_punch_failed"
        | "direct_fast_probe_failed"
        | "retry_send_error"
        | "direct_reclaim_send_error"
        | "fresh_mapping_generation_failed" => Some("direct_probe_failed"),
        "direct_punch_cancelled" => Some("direct_probe_cancelled"),
        "direct_probe_ack_timeout" | "retry_ack_timeout" | "direct_reclaim_ack_timeout" => {
            Some("direct_probe_ack_timeout")
        }
        "direct_probe_budget_exhausted" => Some("direct_probe_budget_exhausted"),
        "direct_validation_suppressed" => Some("direct_validation_suppressed"),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn format_direct_traversal_timeline_detail(
    peer_id: &str,
    generation: u64,
    stage: &str,
    endpoint: Option<SocketAddr>,
    socket_index: Option<usize>,
    candidate_count: Option<usize>,
    sent_probes: Option<u32>,
    detail: &str,
) -> String {
    format!(
        "peer_id={peer_id} generation={generation} stage={stage} endpoint={} socket_index={} candidate_count={} sent_probes={} detail={}",
        endpoint_text(endpoint),
        socket_index.map_or_else(|| "none".to_string(), |value| value.to_string()),
        candidate_count.map_or_else(|| "none".to_string(), |value| value.to_string()),
        sent_probes.map_or_else(|| "none".to_string(), |value| value.to_string()),
        sanitized_validation_detail(detail),
    )
}

fn endpoint_text(endpoint: Option<SocketAddr>) -> String {
    endpoint
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "none".to_string())
}

/// Keep the legacy human detail useful while ensuring local validation owner
/// handles (and anything accidentally labelled as a token) are not copied to
/// the live correlation log.  The typed `/status` record remains unchanged so
/// existing local diagnostics consumers keep working.
fn sanitized_validation_detail(detail: &str) -> String {
    detail
        .split_whitespace()
        .filter(|part| {
            let key = part.split_once('=').map(|(key, _)| key).unwrap_or_default();
            !matches!(
                key,
                "owner" | "owner_token" | "validation_session_id" | "token" | "ticket"
            )
        })
        .take(48)
        .collect::<Vec<_>>()
        .join(" ")
}

#[allow(clippy::too_many_arguments)]
fn format_direct_validation_timeline_detail(
    peer_id: &str,
    generation: u64,
    stage: &str,
    endpoint: Option<SocketAddr>,
    socket_index: Option<usize>,
    candidate_count: Option<usize>,
    sent_probes: Option<u32>,
    metadata: DirectValidationEventMetadata,
    detail: &str,
) -> String {
    format!(
        "peer_id={peer_id} generation={generation} stage={stage} endpoint={} socket_index={} candidate_count={} sent_probes={} request_id={} expected_endpoint={} observed_ack_endpoint={} selected_endpoint={} ack_endpoint_authenticated={} validation_rtt_ms={} detail={}",
        endpoint_text(endpoint),
        socket_index.map_or_else(|| "none".to_string(), |value| value.to_string()),
        candidate_count.map_or_else(|| "none".to_string(), |value| value.to_string()),
        sent_probes.map_or_else(|| "none".to_string(), |value| value.to_string()),
        metadata
            .request_id
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        endpoint_text(metadata.expected_endpoint),
        endpoint_text(metadata.observed_ack_endpoint),
        endpoint_text(metadata.selected_endpoint),
        metadata
            .ack_endpoint_authenticated
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        metadata
            .validation_rtt_ms
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        sanitized_validation_detail(detail),
    )
}

#[cfg(test)]
mod direct_validation_timeline_tests {
    use super::*;

    #[test]
    fn lifecycle_mapping_keeps_terminal_and_ack_boundaries() {
        assert_eq!(
            direct_validation_timeline_event("direct_validation_request_sent"),
            Some("direct_validation_request_sent")
        );
        assert_eq!(
            direct_validation_timeline_event("direct_validation_request_prepared"),
            Some("direct_validation_request_prepared")
        );
        assert_eq!(
            direct_validation_timeline_event("direct_validation_ack_unmatched"),
            Some("direct_validation_ack_unmatched")
        );
        assert_eq!(
            direct_validation_timeline_event("direct_validation_timed_out"),
            Some("direct_validation_timed_out")
        );
        assert_eq!(
            direct_validation_timeline_event("birthday_probe_sent"),
            None
        );
        assert_eq!(
            direct_validation_default_reason("direct_validation_timed_out"),
            Some("direct_validation_timeout")
        );
        assert_eq!(
            direct_traversal_timeline_event("direct_fast_probe_started"),
            Some("direct_fast_probe_started")
        );
        assert_eq!(
            direct_traversal_default_reason("retry_ack_timeout"),
            Some("direct_probe_ack_timeout")
        );
    }

    #[test]
    fn live_detail_redacts_local_owner_handles() {
        let detail = sanitized_validation_detail(
            "owner=123 owner_token=456 request_id=7 generation=9 reason_code=timeout",
        );
        assert!(!detail.contains("owner="));
        assert!(!detail.contains("owner_token="));
        assert!(detail.contains("request_id=7"));
        assert!(detail.contains("reason_code=timeout"));
    }
}
