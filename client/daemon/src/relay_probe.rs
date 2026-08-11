//! Forced-relay encrypted path-probe / path-ack protocol.
//!
//! Direct UDP validation (`transport.rs`) proves the Direct path with a fully
//! daemon-internal request/ACK protocol authenticated by the WireGuard
//! session.  This module is the relay analog: a path-probe is sent FORCED over
//! the relay transport (never the path selector), and only a matching ACK
//! whose REAL ingress was relay sets `RelayPeerConfirmed`.  A local TCP/TLS
//! connect, a queued registration, or a command-queue accept is never enough.
//!
//! Framing mirrors the direct-validation packets: an ICMP echo request
//! (type 8) carrying the probe prefix plus a fixed-size big-endian token
//! (generation, request id, owner token).  The daemon consumes these packets
//! internally — neither the TUN device nor an OS echo reply is involved.

use std::time::{Duration, Instant};

use p2pnet_tun::{Ipv4Packet, Protocol};

/// ICMP echo-request payload prefix marking a forced-relay probe REQUEST.
pub(crate) const RELAY_PROBE_REQUEST_PAYLOAD: &[u8] = b"p2wlan-relay-probe-req";
/// ICMP echo-request payload prefix marking the forced-relay probe ACK.
/// Carries the mirrored token of the request it answers.
pub(crate) const RELAY_PROBE_ACK_PAYLOAD: &[u8] = b"p2wlan-relay-probe-ack";
/// Size of the probe token: generation (8 BE) + request id (2 BE) + owner
/// token (8 BE).
const RELAY_PROBE_TOKEN_BYTES: usize = 18;
/// How long a probe ACK may lag behind its request before the token is stale
/// and must not confirm the relay path.  Generous to tolerate multi-second
/// relay one-way latency (cross-continent or congested links): a probe that
/// was actually answered must confirm even when the ACK rides a slow relay.
pub(crate) const RELAY_PROBE_EXPECTATION_TTL: Duration = Duration::from_secs(30);

/// Kind of a forced-relay probe packet parsed from a decrypted WireGuard
/// datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayProbeKind {
    /// A probe request: the sender asks us to confirm the relay path.
    Request,
    /// A probe acknowledgement: the peer confirms OUR request over the relay.
    Ack,
}

/// Token carried by every forced-relay probe packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelayProbeToken {
    pub(crate) kind: RelayProbeKind,
    /// Network generation the request was built in (initiator-local label;
    /// echoed unchanged so the initiator's owned expectation can match it).
    pub(crate) generation: u64,
    /// Request id of the probe the token belongs to.
    pub(crate) request_id: u16,
    /// Process-wide probe-session owner that originated the request.
    pub(crate) owner_token: u64,
}

/// Build the ICMP echo-request payload of one forced-relay probe: the fixed
/// prefix plus the big-endian token.
pub(crate) fn build_relay_probe_payload(
    kind: RelayProbeKind,
    generation: u64,
    request_id: u16,
    owner_token: u64,
) -> Vec<u8> {
    let prefix = match kind {
        RelayProbeKind::Request => RELAY_PROBE_REQUEST_PAYLOAD,
        RelayProbeKind::Ack => RELAY_PROBE_ACK_PAYLOAD,
    };
    let mut payload = Vec::with_capacity(prefix.len() + RELAY_PROBE_TOKEN_BYTES);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&request_id.to_be_bytes());
    payload.extend_from_slice(&owner_token.to_be_bytes());
    payload
}

/// Parse the forced-relay probe token out of a decrypted WireGuard datagram,
/// or `None` when the packet is not a probe packet.
pub(crate) fn parse_relay_probe_token(packet: &[u8]) -> Option<RelayProbeToken> {
    let ip = Ipv4Packet::new(packet).ok()?;
    if ip.protocol() != Protocol::Icmp {
        return None;
    }
    let icmp = ip.payload();
    if icmp.len() < 8 {
        return None;
    }
    if icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    let payload = &icmp[8..];
    let kind = if payload.starts_with(RELAY_PROBE_REQUEST_PAYLOAD) {
        RelayProbeKind::Request
    } else if payload.starts_with(RELAY_PROBE_ACK_PAYLOAD) {
        RelayProbeKind::Ack
    } else {
        return None;
    };
    let prefix_len = match kind {
        RelayProbeKind::Request => RELAY_PROBE_REQUEST_PAYLOAD.len(),
        RelayProbeKind::Ack => RELAY_PROBE_ACK_PAYLOAD.len(),
    };
    // The full token must follow the prefix: a truncated payload is not a
    // probe packet.
    let token_start = payload
        .len()
        .checked_sub(RELAY_PROBE_TOKEN_BYTES)
        .filter(|start| *start >= prefix_len)?;
    let token = payload.get(token_start..)?;
    let generation = u64::from_be_bytes(token[..8].try_into().ok()?);
    let request_id = u16::from_be_bytes(token[8..10].try_into().ok()?);
    let owner_token = u64::from_be_bytes(token[10..18].try_into().ok()?);
    Some(RelayProbeToken {
        kind,
        generation,
        request_id,
        owner_token,
    })
}

/// The expectation the initiator registers before sending a forced-relay
/// probe.  Only a matching ACK whose real ingress is relay may consume it.
#[derive(Debug, Clone)]
pub(crate) struct RelayProbeExpectation {
    /// Network generation the probe was built in.
    pub(crate) generation: u64,
    /// Request id of the outstanding probe.
    pub(crate) request_id: u16,
    /// Probe-session owner token of the outstanding probe.
    pub(crate) owner_token: u64,
    /// Relay endpoint the probe was sent over (diagnostics).
    pub(crate) relay_endpoint: String,
    /// When the probe was sent; the expectation expires after
    /// [`RELAY_PROBE_EXPECTATION_TTL`].
    pub(crate) sent_at: Instant,
}

impl RelayProbeExpectation {
    /// Whether an incoming ACK token mirrors this outstanding probe.
    pub(crate) fn matches(&self, token: &RelayProbeToken) -> bool {
        self.request_id == token.request_id
            && self.generation == token.generation
            && self.owner_token == token.owner_token
    }

    /// Whether the expectation is still within its validity window.
    pub(crate) fn fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.sent_at) <= RELAY_PROBE_EXPECTATION_TTL
    }

    /// Whether an incoming ACK fully accepts this expectation: the token
    /// mirrors it, it is still fresh, AND the ACK arrived over the SAME relay
    /// the probe was sent on (`ack_ingress`).  Requiring the ingress relay to
    /// match prevents a late ACK from an old relay path from admitting the
    /// current path.
    pub(crate) fn accepts(&self, token: &RelayProbeToken, now: Instant, ack_ingress: &str) -> bool {
        self.matches(token) && self.fresh(now) && self.relay_endpoint == ack_ingress
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_payload_build_and_parse_round_trip() {
        for kind in [RelayProbeKind::Request, RelayProbeKind::Ack] {
            let payload =
                build_relay_probe_payload(kind, 0x1122_3344_5566_7788, 0x1234, 0xdead_beef);
            // Build a full ICMP echo-request IP packet around the payload.
            let packet = Ipv4Packet::build_icmp_echo_request(
                "10.20.0.1".parse().unwrap(),
                "10.20.0.2".parse().unwrap(),
                0x1234,
                1,
                &payload,
            );
            let token = parse_relay_probe_token(&packet)
                .unwrap_or_else(|| panic!("token must parse for {kind:?}"));
            assert_eq!(token.kind, kind);
            assert_eq!(token.generation, 0x1122_3344_5566_7788);
            assert_eq!(token.request_id, 0x1234);
            assert_eq!(token.owner_token, 0xdead_beef);
        }
    }

    #[test]
    fn non_probe_packet_is_rejected() {
        assert!(parse_relay_probe_token(b"not an ip packet").is_none());
        // An IP packet that is ICMP but carries no probe prefix.
        let packet = Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            7,
            1,
            b"ordinary traffic",
        );
        assert!(parse_relay_probe_token(&packet).is_none());
    }

    #[test]
    fn expectation_matches_exact_token_and_expires() {
        let expectation = RelayProbeExpectation {
            generation: 3,
            request_id: 42,
            owner_token: 0xabc,
            relay_endpoint: "tcp://relay.test:18081".to_string(),
            sent_at: Instant::now(),
        };
        let ack = RelayProbeToken {
            kind: RelayProbeKind::Ack,
            generation: 3,
            request_id: 42,
            owner_token: 0xabc,
        };
        assert!(expectation.matches(&ack));
        assert!(expectation.fresh(Instant::now()));
        // Wrong generation or id must not match.
        let wrong = RelayProbeToken {
            kind: RelayProbeKind::Ack,
            generation: 4,
            request_id: 42,
            owner_token: 0xabc,
        };
        assert!(!expectation.matches(&wrong));
        // A request token is not an ACK; matching ignores kind (the caller
        // checks the ingress/kind gate before consuming).
        let request = RelayProbeToken {
            kind: RelayProbeKind::Request,
            generation: 3,
            request_id: 42,
            owner_token: 0xabc,
        };
        assert!(expectation.matches(&request));
    }
}
