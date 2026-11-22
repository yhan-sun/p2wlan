use super::CompactSession;
use ring::hmac;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A separate informational record. The ordinary request and response remain 36 bytes.
/// magic | address family | reserved | session | challenge | port | IP | MAC
pub const ENDPOINT_RECEIPT_SIZE: usize = 54;
const TAG: usize = ENDPOINT_RECEIPT_SIZE - 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EndpointReceipt {
    pub challenge: [u8; 8],
    /// Source of the matching UDP response as seen at the reporter's socket.
    pub observed: SocketAddr,
}

impl EndpointReceipt {
    pub const MAGIC: [u8; 2] = *b"O3";

    pub fn session_hint(bytes: &[u8]) -> Option<u64> {
        if bytes.len() != ENDPOINT_RECEIPT_SIZE || !bytes.starts_with(&Self::MAGIC) {
            return None;
        }
        Some(u64::from_be_bytes(bytes[4..12].try_into().ok()?))
    }

    fn valid(&self) -> bool {
        self.observed.port() != 0
            && !self.observed.ip().is_unspecified()
            && !self.observed.ip().is_multicast()
            && !matches!(self.observed.ip(), IpAddr::V4(ip) if ip.is_broadcast())
            && !matches!(self.observed, SocketAddr::V6(v6) if v6.scope_id() != 0)
    }
}

impl CompactSession {
    pub fn encode_endpoint_receipt(
        &self,
        receipt: EndpointReceipt,
    ) -> Option<[u8; ENDPOINT_RECEIPT_SIZE]> {
        if !receipt.valid() {
            return None;
        }
        let mut bytes = [0; ENDPOINT_RECEIPT_SIZE];
        bytes[..2].copy_from_slice(&EndpointReceipt::MAGIC);
        bytes[4..12].copy_from_slice(&self.id.to_be_bytes());
        bytes[12..20].copy_from_slice(&receipt.challenge);
        bytes[20..22].copy_from_slice(&receipt.observed.port().to_be_bytes());
        match receipt.observed.ip() {
            IpAddr::V4(ip) => {
                bytes[2] = 4;
                bytes[22..26].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                bytes[2] = 6;
                bytes[22..TAG].copy_from_slice(&ip.octets());
            }
        }
        let tag = hmac::sign(&self.outbound, &bytes[..TAG]);
        bytes[TAG..].copy_from_slice(&tag.as_ref()[..16]);
        Some(bytes)
    }

    pub fn decode_endpoint_receipt(&self, bytes: &[u8]) -> Option<EndpointReceipt> {
        if EndpointReceipt::session_hint(bytes)? != self.id
            || bytes[3] != 0
            || !Self::valid_tag(&self.inbound, bytes)
        {
            return None;
        }
        let ip = match bytes[2] {
            4 if bytes[26..TAG] == [0; 12] => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[22..26]).ok()?))
            }
            6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[22..TAG]).ok()?)),
            _ => return None,
        };
        let receipt = EndpointReceipt {
            challenge: bytes[12..20].try_into().ok()?,
            observed: SocketAddr::new(ip, u16::from_be_bytes(bytes[20..22].try_into().ok()?)),
        };
        receipt.valid().then_some(receipt)
    }
}
