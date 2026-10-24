//! Only packets accepted by an existing capture parser consult the registry.
//! Parsing never constructs an original read, owner, Full or native fact.
use super::CaptureFailure;
use crate::business_evidence::tcp_frame::{parse_tcp_segment, TcpSegment};
use crate::business_evidence::{parse_os_udp, ParsedOsUdp};

pub(super) fn capture<'a, T>(
    packet: &'a [u8],
    enter: impl FnOnce(Option<ParsedOsUdp>, Option<TcpSegment<'a>>) -> Result<Option<T>, CaptureFailure>,
) -> Result<Option<T>, CaptureFailure> {
    let udp = parse_os_udp(packet).ok();
    let tcp = parse_tcp_segment(packet).ok();
    if udp.is_none() && tcp.is_none() {
        return Ok(None);
    }
    enter(udp, tcp)
}

#[cfg(all(unix, test))]
mod tests;
