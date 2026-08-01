/// IP protocol numbers (from IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// ICMP (1)
    Icmp = 1,
    /// IGMP (2)
    Igmp = 2,
    /// TCP (6)
    Tcp = 6,
    /// UDP (17)
    Udp = 17,
    /// ICMPv6 (58)
    Icmpv6 = 58,
    /// Unknown protocol
    Unknown = 255,
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Icmp,
            2 => Protocol::Igmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            _ => Protocol::Unknown,
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Igmp => write!(f, "IGMP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmpv6 => write!(f, "ICMPv6"),
            Protocol::Unknown => write!(f, "Unknown({})", *self as u8),
        }
    }
}
