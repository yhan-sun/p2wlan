/// Encode an Auth Register frame payload.
///
/// Returns the binary payload (without the 8-byte frame header).
pub fn encode_auth_register(node_id: &str, ticket: &str) -> std::result::Result<Vec<u8>, String> {
    let node_id_bytes = node_id.as_bytes();
    if node_id_bytes.is_empty() || node_id_bytes.len() > 255 {
        return Err(format!(
            "node_id length {} not in 1..255",
            node_id_bytes.len()
        ));
    }
    if std::str::from_utf8(node_id_bytes).is_err() {
        return Err("node_id is not valid UTF-8".to_string());
    }

    let ticket_bytes = ticket.as_bytes();
    if ticket_bytes.is_empty() || ticket_bytes.len() > MAX_TICKET_LEN {
        return Err(format!(
            "ticket length {} not in 1..{MAX_TICKET_LEN}",
            ticket_bytes.len()
        ));
    }

    let total_len = 1 + node_id_bytes.len() + 2 + ticket_bytes.len();
    let mut payload = Vec::with_capacity(total_len);

    // node_id_len (u8)
    payload.push(node_id_bytes.len() as u8);
    // node_id
    payload.extend_from_slice(node_id_bytes);
    // ticket_len (u16 BE)
    payload.extend_from_slice(&(ticket_bytes.len() as u16).to_be_bytes());
    // ticket
    payload.extend_from_slice(ticket_bytes);

    Ok(payload)
}

/// Decode an Auth Register frame payload.
///
/// Returns `(node_id, ticket_string)`.
pub fn decode_auth_register(payload: &[u8]) -> std::result::Result<(String, String), String> {
    if payload.is_empty() {
        return Err("auth register payload empty".to_string());
    }

    let node_id_len = payload[0] as usize;
    if node_id_len == 0 || node_id_len > 255 {
        return Err(format!("invalid node_id_len: {node_id_len}"));
    }
    if payload.len() < 1 + node_id_len + 2 {
        return Err("auth register payload truncated at node_id".to_string());
    }

    let node_id_bytes = &payload[1..1 + node_id_len];
    let node_id = std::str::from_utf8(node_id_bytes)
        .map_err(|e| format!("node_id is not valid UTF-8: {e}"))?;
    if node_id.is_empty() {
        return Err("node_id is empty".to_string());
    }

    let ticket_start = 1 + node_id_len;
    let ticket_len =
        u16::from_be_bytes([payload[ticket_start], payload[ticket_start + 1]]) as usize;

    if ticket_len == 0 {
        return Err("ticket_len is 0".to_string());
    }
    if ticket_len > MAX_TICKET_LEN {
        return Err(format!(
            "ticket_len {ticket_len} exceeds max {MAX_TICKET_LEN}"
        ));
    }

    let ticket_data_start = ticket_start + 2;
    if payload.len() < ticket_data_start + ticket_len {
        return Err("auth register payload truncated at ticket".to_string());
    }

    // Exact consumption: no trailing bytes allowed
    if payload.len() != ticket_data_start + ticket_len {
        return Err(format!(
            "auth register payload has {} trailing bytes",
            payload.len() - (ticket_data_start + ticket_len)
        ));
    }

    let ticket_bytes = &payload[ticket_data_start..ticket_data_start + ticket_len];
    let ticket =
        std::str::from_utf8(ticket_bytes).map_err(|e| format!("ticket is not valid UTF-8: {e}"))?;

    Ok((node_id.to_string(), ticket.to_string()))
}

// ============================================================
// Network binding key
// ============================================================
