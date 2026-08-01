/// Compute the Internet checksum (RFC 1071) for a byte slice.
fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd-length data
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold carries
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}
