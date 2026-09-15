/// Offer-ingress deduplication and per-peer rate limiting.
///
/// A duplicate or rate-limited offer must not touch candidate state (no
/// candidate apply, no fresh-prediction transaction, no punch trigger): the
/// exact-duplicate fingerprint within the dedup window is the strongest
/// "nothing changed" signal, and the apply-rate window bounds how often a
/// churning peer (including an old client retransmitting every few seconds)
/// can drive candidate-plane work.  Handshake-carrying offers are still
/// answered: a crossing rekey must never be dropped by the rate limiter.
const OFFER_INGRESS_DEDUP_WINDOW: Duration = Duration::from_secs(2);
const OFFER_INGRESS_APPLY_WINDOW: Duration = Duration::from_secs(5);
const OFFER_INGRESS_MAX_APPLIES: u32 = 4;

/// Per-peer offer-ingress record.
struct OfferIngressRecord {
    /// Payload fingerprint (candidates + sources + expiry).
    fingerprint: [u8; 32],
    /// Sender-identity fingerprint: two offers with an identical payload but
    /// a DIFFERENT sender public key are never duplicates (a key change is a
    /// new incarnation).
    sender_fingerprint: [u8; 32],
    /// Last seen time of any offer (dedup window).
    last_seen_at: Instant,
    /// Candidate-plane applies within the current apply window.
    apply_count: u32,
    apply_window_started_at: Instant,
    /// Whether the last offer was admitted (for diagnostics ordering).
    last_verdict: &'static str,
    /// Whether any offer was recorded before: the first offer of a payload is
    /// never a duplicate, even when its age would be zero.
    seen_once: bool,
}

/// Verdict for an incoming offer, decided BEFORE any candidate-plane state is
/// touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfferIngressVerdict {
    /// The offer may apply candidates and start a punch session.
    Apply,
    /// Byte-identical payload seen within the dedup window: no candidate
    /// apply, no fresh transaction, no punch (the running session already
    /// covers it).  The handshake part is still handled.
    Duplicate,
    /// The peer exceeded the per-window apply rate: candidate apply and
    /// punch are suppressed; the handshake part is still handled.
    RateLimited,
}

impl Daemon {
    /// Decide whether an offer may touch candidate-plane state.
    ///
    /// Runs before `fresh_prediction_transaction` and before the responder
    /// worker enqueue: repeated/old offers from a churning peer can no longer
    /// trigger candidate applies or fresh-prediction transactions.
    async fn offer_ingress_verdict(
        &self,
        from_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidates_expires_at_ms: Option<u64>,
        sender_public_key: Option<&str>,
    ) -> OfferIngressVerdict {
        let now = Instant::now();
        let fingerprint = crate::peer::fresh_payload_hash(
            candidates,
            candidate_sources,
            candidates_expires_at_ms,
        );
        let sender_fingerprint = sender_public_key
            .map(|key| crate::peer::fresh_payload_hash(&[key.to_string()], &HashMap::new(), None))
            .unwrap_or([0u8; 32]);
        let mut ingress = self
            .offer_ingress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = ingress
            .entry(from_node_id.to_string())
            .or_insert(OfferIngressRecord {
                fingerprint,
                sender_fingerprint,
                last_seen_at: now,
                apply_count: 0,
                apply_window_started_at: now,
                last_verdict: "apply",
                seen_once: false,
            });
        if record.seen_once
            && record.fingerprint == fingerprint
            && record.sender_fingerprint == sender_fingerprint
            && now.duration_since(record.last_seen_at) <= OFFER_INGRESS_DEDUP_WINDOW
        {
            record.last_seen_at = now;
            record.last_verdict = "duplicate";
            return OfferIngressVerdict::Duplicate;
        }
        if now.duration_since(record.apply_window_started_at) > OFFER_INGRESS_APPLY_WINDOW {
            record.apply_count = 0;
            record.apply_window_started_at = now;
        }
        if record.apply_count >= OFFER_INGRESS_MAX_APPLIES {
            record.last_seen_at = now;
            record.last_verdict = "rate_limited";
            return OfferIngressVerdict::RateLimited;
        }
        record.fingerprint = fingerprint;
        record.last_seen_at = now;
        record.apply_count = record.apply_count.saturating_add(1);
        record.seen_once = true;
        record.last_verdict = "apply";
        OfferIngressVerdict::Apply
    }
}
