//! Outbound UDP liveness probing via a well-formed DNS A query.
//!
//! Field evidence: the NetEase UU remote implementation decided "outbound UDP
//! blocked" by firing EMPTY datagrams (`sendto(b"\x00"*16)`) and waiting on
//! `recvfrom`. Public DNS servers almost never answer a malformed/empty
//! datagram, so the "got a response" path was effectively unreachable and the
//! verdict was unreliable. We instead send a minimal legal DNS A query, which
//! a public resolver answers whether the answer is NOERROR or NXDOMAIN — so
//! "any response" is a dependable outbound+inbound-UDP-reachable signal.

/// Conservative three-state verdict for outbound UDP reachability.
///
/// Only `Blocked` may accelerate the recovery path into relay fallback and
/// stamp the `firewall_blocked` attribution. `Unknown` (socket/system error)
/// must NEVER drive a decision — a socket that cannot be created says nothing
/// about whether UDP egress is firewalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessVerdict {
    /// At least one target answered within its round timeout: outbound UDP
    /// is reachable; the punch failure has another cause (window miss / C=0).
    Ok,
    /// Every target × every round produced no response: outbound UDP is
    /// likely firewalled.
    Blocked,
    /// Socket creation / system error: not used for any decision, recorded
    /// only.
    Unknown,
}

/// Build a minimal legal DNS A-record query: 12-byte header (RD set,
/// QDCOUNT=1) + one single-label question of `type A, class IN`.
pub fn build_dns_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 1 + name.len() + 1 + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD bit set, zero answers expected
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT = 1
    q.extend_from_slice(&[0u8, 0, 0, 0, 0, 0]); // ANCOUNT/NSCOUNT/ARCOUNT
    q.push(name.len() as u8); // single label length
    q.extend_from_slice(name.as_bytes());
    q.push(0); // root terminator
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QTYPE A
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS IN
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_is_well_formed() {
        let q = build_dns_a_query(0x1234, "a");
        // 12-byte header + question (1 len byte + "a" + 0 terminator + 2 type + 2 class)
        assert_eq!(q.len(), 19, "DNS A query for single-label 'a' is 19 bytes");
        // header
        assert_eq!(&q[0..2], &[0x12, 0x34], "transaction id");
        // RD bit set (0x0100 at bytes 2..4), QDCOUNT=1
        assert_eq!(q[2], 0x01, "RD bit");
        assert_eq!(q[3], 0x00, "flags high byte zero");
        assert_eq!(&q[4..6], &[0x00, 0x01], "QDCOUNT == 1");
        assert_eq!(&q[6..12], &[0, 0, 0, 0, 0, 0], "ANCOUNT/NSCOUNT/ARCOUNT zero");
        // question
        assert_eq!(q[12], 1, "single label length 1");
        assert_eq!(q[13], b'a', "label byte 'a'");
        assert_eq!(q[14], 0, "name terminator");
        assert_eq!(&q[15..17], &[0x00, 0x01], "QTYPE A");
        assert_eq!(&q[17..19], &[0x00, 0x01], "QCLASS IN");
    }
}
