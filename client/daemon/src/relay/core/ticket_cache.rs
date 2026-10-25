// Both maps remain bounded even as a control catalog rotates keys. Active
// refresh locks cannot be evicted: every holder/waiter owns an Arc clone.
const MAX_RELAY_TICKET_KEYS: usize = 128;
const MAX_RELAY_TICKET_AUDIENCE_BYTES: usize = 1024;
const MAX_RELAY_TICKET_REGION_BYTES: usize = 256;
const MAX_RELAY_TICKET_BYTES: usize = 16 * 1024;

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

impl RelayTicketKey {
    fn checked(audience: &str, region: &str) -> Result<Self> {
        for (resource, length, limit) in [
            (
                "relay_ticket_audience_bytes",
                audience.len(),
                MAX_RELAY_TICKET_AUDIENCE_BYTES,
            ),
            (
                "relay_ticket_region_bytes",
                region.len(),
                MAX_RELAY_TICKET_REGION_BYTES,
            ),
        ] {
            if length > limit {
                return Err(DaemonError::ResourceLimit { resource, limit });
            }
        }
        Ok(Self {
            audience: audience.to_owned(),
            region: region.to_owned(),
        })
    }
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
        self.ticket_with_expiry_for(audience, region)
            .await
            .map(|(ticket, _)| ticket)
    }

    /// Return the credential and its own server expiry as one owned pair.
    /// A later cache eviction cannot strip renewal metadata from this result.
    pub(crate) async fn ticket_with_expiry_for(
        &self,
        audience: &str,
        region: &str,
    ) -> Result<(String, i64)> {
        let key = RelayTicketKey::checked(audience, region)?;

        if let Some(ticket) = self.cached_ticket(&key).await {
            return Ok(ticket);
        }

        let refresh_lock = self.refresh_lock_for(&key).await?;

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

        self.cache_ticket(key, &ticket, expires_at).await?;

        Ok((ticket, expires_at))
    }

    async fn refresh_lock_for(&self, key: &RelayTicketKey) -> Result<Arc<Mutex<()>>> {
        let mut locks = self.refresh_locks.lock().await;
        if let Some(lock) = locks.get(key) {
            return Ok(lock.clone());
        }
        if locks.len() >= MAX_RELAY_TICKET_KEYS {
            // Under this map lock no other caller can take a new Arc. A sole
            // map reference proves there is no holder or queued waiter.
            locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        }
        if locks.len() >= MAX_RELAY_TICKET_KEYS {
            return Err(DaemonError::ResourceLimit {
                resource: "relay_ticket_refresh_keys",
                limit: MAX_RELAY_TICKET_KEYS,
            });
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key.clone(), lock.clone());
        Ok(lock)
    }

    async fn cache_ticket(&self, key: RelayTicketKey, ticket: &str, expires_at: i64) -> Result<()> {
        if ticket.len() > MAX_RELAY_TICKET_BYTES {
            return Err(DaemonError::ResourceLimit {
                resource: "relay_ticket_bytes",
                limit: MAX_RELAY_TICKET_BYTES,
            });
        }
        let mut entries = self.entries.lock().await;
        let valid_after = now_unix().saturating_add(RELAY_TICKET_REFRESH_MARGIN_SECS);
        entries.retain(|_, entry| entry.expires_at > valid_after);
        if !entries.contains_key(&key) && entries.len() >= MAX_RELAY_TICKET_KEYS {
            let victim = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone());
            let Some(victim) = victim else {
                return Err(DaemonError::ResourceLimit {
                    resource: "relay_ticket_cache_keys",
                    limit: MAX_RELAY_TICKET_KEYS,
                });
            };
            // Only a cached copy is evicted. Existing transport credentials
            // and refresh ownership remain with their original owners.
            entries.remove(&victim);
        }
        entries.insert(
            key,
            CachedRelayTicket {
                ticket: ticket.to_owned(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn cached_ticket(&self, key: &RelayTicketKey) -> Option<(String, i64)> {
        self.entries.lock().await.get(key).and_then(|entry| {
            if entry.expires_at > now_unix() + RELAY_TICKET_REFRESH_MARGIN_SECS {
                Some((entry.ticket.clone(), entry.expires_at))
            } else {
                None
            }
        })
    }

    /// Force-refresh the cached ticket for `(audience, region)` and return the
    /// new (ticket, expiry) pair.  Used by the proactive renewal so the new
    /// connection always registers with a ticket that outlives the old one.
    pub(crate) async fn refresh_ticket(
        &self,
        audience: &str,
        region: &str,
    ) -> Result<(String, i64)> {
        let key = RelayTicketKey::checked(audience, region)?;
        let refresh_lock = self.refresh_lock_for(&key).await?;
        let _guard = refresh_lock.lock().await;
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
        self.cache_ticket(key, &ticket, expires_at).await?;
        Ok((ticket, expires_at))
    }
}

#[cfg(test)]
mod ticket_cache_tests {
    include!("ticket_cache_tests.rs");
}
