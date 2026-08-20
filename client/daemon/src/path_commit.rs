//! Synthetic path-commit protocol: prove a path can carry business in BOTH
//! directions without depending on *natural* traffic actually flowing.
//!
//! The relay-first business gate (`PeerConnection::relay_first_business_*`)
//! requires both local business directions to have crossed the confirmed relay
//! before Direct may win the data plane.  That protects the WireGuard
//! counter-commit invariant (the first plaintext commits on a path proven for
//! both directions, so it cannot be committed on relay then re-committed on
//! direct).  But for one-directional traffic — telemetry, video push, unidirectional
//! UDP, heartbeat-only — the natural *receive* direction never happens, so the
//! gate holds forever and the peer is stranded on relay despite a confirmed,
//! encrypted Direct path (audit P0-4).
//!
//! A path-commit probe solves this the way the relay path-probe
//! (`relay_probe.rs`) confirms the relay: a request is sent FORCED over the
//! confirmed relay transport and only a matching ACK whose real ingress was the
//! same relay accepts it.  Because the probe is business-shaped (an encrypted
//! WireGuard datagram) and proves BOTH directions over the same transport, it is
//! an *alternative* proof of the same invariant the natural exchange establishes.
//! Receiving a path-commit ACK may therefore close the relay-first business
//! gate; it must never, by itself, make Direct the active path — Direct
//! promotion still requires its own generation-bound encrypted validation.
//!
//! Framing mirrors `relay_probe.rs`: an ICMP echo-request (type 8) carrying the
//! probe prefix plus a fixed-size big-endian token (generation, request id,
//! owner token).  The daemon consumes these packets internally.

use std::time::{Duration, Instant};

use p2pnet_tun::{Ipv4Packet, Protocol};

/// ICMP echo-request payload prefix marking a path-commit REQUEST.
pub(crate) const PATH_COMMIT_REQUEST_PAYLOAD: &[u8] = b"p2wlan-pathcommit-req";
/// ICMP echo-request payload prefix marking the path-commit ACK.  Carries the
/// mirrored token of the request it answers.
pub(crate) const PATH_COMMIT_ACK_PAYLOAD: &[u8] = b"p2wlan-pathcommit-ack";
/// Size of the token: generation (8 BE) + request id (2 BE) + owner token (8 BE).
const PATH_COMMIT_TOKEN_BYTES: usize = 18;
/// How long a path-commit ACK may lag its request before the token is stale and
/// must not close the gate.  Same generosity as the relay path-probe: a probe
/// that was actually answered over a slow relay must still commit.
pub(crate) const PATH_COMMIT_EXPECTATION_TTL: Duration = Duration::from_secs(30);

/// Kind of a path-commit packet parsed from a decrypted WireGuard datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathCommitKind {
    /// A path-commit request: the sender asks us to commit the path over relay.
    Request,
    /// A path-commit acknowledgement: the peer confirms OUR request over relay.
    Ack,
}

/// Token carried by every path-commit packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathCommitToken {
    pub(crate) kind: PathCommitKind,
    /// Network generation the request was built in (echoed unchanged so the
    /// initiator's owned expectation can match it).
    pub(crate) generation: u64,
    /// Request id of the probe the token belongs to.
    pub(crate) request_id: u16,
    /// Process-wide probe-session owner that originated the request.
    pub(crate) owner_token: u64,
}

/// Build the ICMP echo-request payload of one path-commit packet: the fixed
/// prefix plus the big-endian token.
pub(crate) fn build_path_commit_payload(
    kind: PathCommitKind,
    generation: u64,
    request_id: u16,
    owner_token: u64,
) -> Vec<u8> {
    let prefix = match kind {
        PathCommitKind::Request => PATH_COMMIT_REQUEST_PAYLOAD,
        PathCommitKind::Ack => PATH_COMMIT_ACK_PAYLOAD,
    };
    let mut payload = Vec::with_capacity(prefix.len() + PATH_COMMIT_TOKEN_BYTES);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&request_id.to_be_bytes());
    payload.extend_from_slice(&owner_token.to_be_bytes());
    payload
}

/// Parse the path-commit token out of a decrypted WireGuard datagram, or `None`
/// when the packet is not a path-commit packet.
pub(crate) fn parse_path_commit_token(packet: &[u8]) -> Option<PathCommitToken> {
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
    let kind = if payload.starts_with(PATH_COMMIT_REQUEST_PAYLOAD) {
        PathCommitKind::Request
    } else if payload.starts_with(PATH_COMMIT_ACK_PAYLOAD) {
        PathCommitKind::Ack
    } else {
        return None;
    };
    let prefix_len = match kind {
        PathCommitKind::Request => PATH_COMMIT_REQUEST_PAYLOAD.len(),
        PathCommitKind::Ack => PATH_COMMIT_ACK_PAYLOAD.len(),
    };
    let token_start = payload
        .len()
        .checked_sub(PATH_COMMIT_TOKEN_BYTES)
        .filter(|start| *start >= prefix_len)?;
    let token = payload.get(token_start..)?;
    let generation = u64::from_be_bytes(token[..8].try_into().ok()?);
    let request_id = u16::from_be_bytes(token[8..10].try_into().ok()?);
    let owner_token = u64::from_be_bytes(token[10..18].try_into().ok()?);
    Some(PathCommitToken {
        kind,
        generation,
        request_id,
        owner_token,
    })
}

/// The expectation the initiator registers before sending a path-commit probe.
/// Only a matching ACK whose real ingress is the same confirmed relay may
/// consume it — mirroring the relay path-probe's acceptance rules.
#[derive(Debug, Clone)]
pub(crate) struct PathCommitExpectation {
    /// Network generation the probe was built in.
    pub(crate) generation: u64,
    /// Request id of the outstanding probe.
    pub(crate) request_id: u16,
    /// Probe-session owner token of the outstanding probe.
    pub(crate) owner_token: u64,
    /// Relay endpoint the probe was sent over (diagnostics).
    pub(crate) relay_endpoint: String,
    /// When the probe was sent; the expectation expires after
    /// [`PATH_COMMIT_EXPECTATION_TTL`].
    pub(crate) sent_at: Instant,
}

impl PathCommitExpectation {
    /// Whether an incoming token mirrors this outstanding probe (kind checked
    /// by the caller, matching the relay-probe convention).
    pub(crate) fn matches(&self, token: &PathCommitToken) -> bool {
        self.request_id == token.request_id
            && self.generation == token.generation
            && self.owner_token == token.owner_token
    }

    /// Whether the expectation is still within its validity window.
    pub(crate) fn fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.sent_at) <= PATH_COMMIT_EXPECTATION_TTL
    }

    /// Whether an incoming ACK fully accepts this expectation: the token
    /// mirrors it, it is still fresh, AND the ACK arrived over the SAME relay
    /// the probe was sent on (`ack_ingress`).  A late ACK from a different relay
    /// must not commit the current path.
    pub(crate) fn accepts(&self, token: &PathCommitToken, now: Instant, ack_ingress: &str) -> bool {
        self.matches(token) && self.fresh(now) && self.relay_endpoint == ack_ingress
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_commit_payload_build_and_parse_round_trip() {
        for kind in [PathCommitKind::Request, PathCommitKind::Ack] {
            let payload =
                build_path_commit_payload(kind, 0x1122_3344_5566_7788, 0x1234, 0xdead_beef);
            let packet = Ipv4Packet::build_icmp_echo_request(
                "10.20.0.1".parse().unwrap(),
                "10.20.0.2".parse().unwrap(),
                0x1234,
                1,
                &payload,
            );
            let token = parse_path_commit_token(&packet)
                .unwrap_or_else(|| panic!("token must parse for {kind:?}"));
            assert_eq!(token.kind, kind);
            assert_eq!(token.generation, 0x1122_3344_5566_7788);
            assert_eq!(token.request_id, 0x1234);
            assert_eq!(token.owner_token, 0xdead_beef);
        }
    }

    #[test]
    fn non_path_commit_packet_is_rejected() {
        assert!(parse_path_commit_token(b"not an ip packet").is_none());
        // A relay path-probe packet must NOT parse as a path-commit packet:
        // the two prefixes are distinct and must not cross-confirm.
        let relay_probe = crate::relay_probe::build_relay_probe_payload(
            crate::relay_probe::RelayProbeKind::Request,
            7,
            1,
            2,
        );
        let packet = Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            7,
            1,
            &relay_probe,
        );
        assert!(parse_path_commit_token(&packet).is_none());
        // Ordinary traffic is also rejected.
        let ordinary = Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            7,
            1,
            b"ordinary traffic",
        );
        assert!(parse_path_commit_token(&ordinary).is_none());
    }

    #[test]
    fn path_commit_expectation_matches_exact_token_and_expires() {
        let expectation = PathCommitExpectation {
            generation: 3,
            request_id: 42,
            owner_token: 0xabc,
            relay_endpoint: "tcp://relay.test:18081".to_string(),
            sent_at: Instant::now(),
        };
        let ack = PathCommitToken {
            kind: PathCommitKind::Ack,
            generation: 3,
            request_id: 42,
            owner_token: 0xabc,
        };
        assert!(expectation.matches(&ack));
        assert!(expectation.fresh(Instant::now()));
        assert!(expectation.accepts(&ack, Instant::now(), "tcp://relay.test:18081"));
        // A wrong ingress relay must not accept.
        assert!(!expectation.accepts(&ack, Instant::now(), "tcp://other.test:9999"));
        // A wrong generation must not match.
        let wrong = PathCommitToken {
            kind: PathCommitKind::Ack,
            generation: 4,
            request_id: 42,
            owner_token: 0xabc,
        };
        assert!(!expectation.matches(&wrong));
    }
}
