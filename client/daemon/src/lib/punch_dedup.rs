#[derive(Clone, Default)]
struct PunchAttemptDeduplicator {
    recent_starts: Arc<tokio::sync::Mutex<HashMap<String, PunchAttemptRecord>>>,
}

#[derive(Clone, Copy)]
struct PunchAttemptRecord {
    started_at: Instant,
    priority: u8,
}

impl PunchAttemptDeduplicator {
    async fn claim(&self, peer_id: &str) -> bool {
        self.claim_with_window_and_priority(peer_id, PUNCH_SESSION_DEDUP_WINDOW, 1)
            .await
    }

    async fn claim_with_window(&self, peer_id: &str, window: Duration) -> bool {
        self.claim_with_window_and_priority(peer_id, window, 0)
            .await
    }

    async fn claim_with_window_and_priority(
        &self,
        peer_id: &str,
        window: Duration,
        priority: u8,
    ) -> bool {
        let now = Instant::now();
        let mut starts = self.recent_starts.lock().await;
        starts.retain(|_, record| now.duration_since(record.started_at) < window);
        if let Some(record) = starts.get(peer_id) {
            if record.priority >= priority {
                return false;
            }
        }
        starts.insert(
            peer_id.to_string(),
            PunchAttemptRecord {
                started_at: now,
                priority,
            },
        );
        true
    }
}

fn should_cancel_maintenance_offer(
    is_rekey: bool,
    has_session: bool,
    needs_rekey: bool,
    expired: bool,
) -> bool {
    if is_rekey {
        has_session && !needs_rekey && !expired
    } else {
        has_session
    }
}
