#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RelayTicketKey {
    audience: String,
    region: String,
}

#[derive(Debug, Clone)]
struct CachedRelayTicket {
    ticket: String,
    expires_at: i64,
}

/// In-memory relay ticket cache keyed by (audience, region).
///
/// Tokens are never persisted or placed in diagnostics. A per-key async lock
/// merges concurrent refreshes for the same relay audience.
pub struct RelayTicketCache {
    control_client: ControlClient,
    entries: Mutex<HashMap<RelayTicketKey, CachedRelayTicket>>,
    refresh_locks: Mutex<HashMap<RelayTicketKey, Arc<Mutex<()>>>>,
}

impl RelayTicketCache {
    pub fn new(control_client: ControlClient) -> Self {
        Self {
            control_client,
            entries: Mutex::new(HashMap::new()),
            refresh_locks: Mutex::new(HashMap::new()),
        }
    }

    pub async fn ticket_for(&self, audience: &str, region: &str) -> Result<String> {
        let key = RelayTicketKey {
            audience: audience.to_string(),
            region: region.to_string(),
        };

        if let Some(ticket) = self.cached_ticket(&key).await {
            return Ok(ticket);
        }

        let refresh_lock = {
            let mut locks = self.refresh_locks.lock().await;
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };

        let _guard = refresh_lock.lock().await;

        if let Some(ticket) = self.cached_ticket(&key).await {
            return Ok(ticket);
        }

        let (ticket, expires_at) = self
            .control_client
            .fetch_relay_ticket(&key.audience, &key.region)
            .await?;

        if ticket.trim().is_empty() {
            return Err(DaemonError::ControlPlane(
                "relay ticket response contained an empty ticket".into(),
            ));
        }
        if expires_at <= now_unix() + RELAY_TICKET_REFRESH_MARGIN_SECS {
            return Err(DaemonError::ControlPlane(
                "relay ticket expires too soon".into(),
            ));
        }

        self.entries.lock().await.insert(
            key.clone(),
            CachedRelayTicket {
                ticket: ticket.clone(),
                expires_at,
            },
        );

        Ok(ticket)
    }

    async fn cached_ticket(&self, key: &RelayTicketKey) -> Option<String> {
        self.entries.lock().await.get(key).and_then(|entry| {
            if entry.expires_at > now_unix() + RELAY_TICKET_REFRESH_MARGIN_SECS {
                Some(entry.ticket.clone())
            } else {
                None
            }
        })
    }
}
