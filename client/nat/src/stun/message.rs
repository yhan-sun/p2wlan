/// A complete STUN message (header + attributes).
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Message type (e.g. BINDING_REQUEST, BINDING_RESPONSE).
    pub msg_type: u16,
    /// 12-byte transaction ID.
    pub transaction_id: [u8; 12],
    /// Parsed attributes.
    pub attributes: Vec<StunAttribute>,
    /// Raw bytes of the entire message (set after decode or encode).
    pub raw: Vec<u8>,
}

impl StunMessage {
    /// Create a new STUN message with a random transaction ID.
    pub fn new(msg_type: u16) -> Self {
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut transaction_id);

        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
            raw: Vec::new(),
        }
    }

    /// Create a new STUN message with a specific transaction ID.
    pub fn with_transaction_id(msg_type: u16, transaction_id: [u8; 12]) -> Self {
        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
            raw: Vec::new(),
        }
    }

    /// Create a Binding Request message.
    pub fn binding_request() -> Self {
        Self::new(BINDING_REQUEST)
    }

    /// Add an attribute.
    pub fn add_attribute(&mut self, attr: StunAttribute) {
        self.attributes.push(attr);
    }

    /// Encode this message to wire format.
    pub fn encode(&mut self) -> Vec<u8> {
        // Encode all attributes into a buffer
        let mut attr_buf = Vec::new();
        for attr in &self.attributes {
            let (attr_type, value) = attr.encode(&self.transaction_id);
            attr_buf.extend_from_slice(&attr_type.to_be_bytes());
            attr_buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            attr_buf.extend_from_slice(&value);
            // Pad to 4-byte boundary
            let padding = (4 - (value.len() % 4)) % 4;
            attr_buf.resize(attr_buf.len() + padding, 0);
        }

        // Build header
        let mut buf = Vec::with_capacity(STUN_HEADER_SIZE + attr_buf.len());
        buf.extend_from_slice(&self.msg_type.to_be_bytes());
        buf.extend_from_slice(&(attr_buf.len() as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE_BYTES);
        buf.extend_from_slice(&self.transaction_id);
        buf.extend_from_slice(&attr_buf);

        self.raw = buf.clone();
        buf
    }

    /// Encode with FINGERPRINT attribute appended.
    pub fn encode_with_fingerprint(&mut self) -> Vec<u8> {
        // First encode without fingerprint
        let buf_no_fp = self.encode();

        // Compute fingerprint over the message (header + attributes, without FP)
        let fp = compute_fingerprint(&buf_no_fp);

        // Append FINGERPRINT attribute
        let mut buf = buf_no_fp;
        buf.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes()); // length = 4
        buf.extend_from_slice(&fp.to_be_bytes());

        // Update message length in header (original length + 8 bytes for FP attribute)
        let new_len = (u16::from_be_bytes([buf[2], buf[3]]) + 8).to_be_bytes();
        buf[2] = new_len[0];
        buf[3] = new_len[1];

        self.raw = buf.clone();
        buf
    }

    /// Decode a STUN message from wire format.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < STUN_HEADER_SIZE {
            return Err(NatError::InvalidStunMessage(format!(
                "message too short: {} bytes (need at least {})",
                data.len(),
                STUN_HEADER_SIZE
            )));
        }

        // Check first two bits are 0 (STUN message indicator)
        if data[0] & 0xC0 != 0 {
            return Err(NatError::InvalidStunMessage(
                "first two bits are not zero (not a STUN message)".into(),
            ));
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        if cookie != MAGIC_COOKIE {
            return Err(NatError::InvalidStunMessage(format!(
                "invalid magic cookie: 0x{:08X} (expected 0x{:08X})",
                cookie, MAGIC_COOKIE
            )));
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        if data.len() < STUN_HEADER_SIZE + msg_len {
            return Err(NatError::InvalidStunMessage(format!(
                "message truncated: have {} bytes, header says {}",
                data.len(),
                STUN_HEADER_SIZE + msg_len
            )));
        }

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = STUN_HEADER_SIZE;
        let end = STUN_HEADER_SIZE + msg_len;

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > end {
                return Err(NatError::InvalidStunMessage(format!(
                    "attribute 0x{:04X} length {} exceeds message boundary",
                    attr_type, attr_len
                )));
            }

            let attr_data = &data[offset..offset + attr_len];
            let attr = StunAttribute::decode(attr_type, attr_data, &transaction_id)?;
            attributes.push(attr);

            // Advance past padding
            offset += attr_len;
            let padding = (4 - (attr_len % 4)) % 4;
            offset += padding;
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
            raw: data.to_vec(),
        })
    }

    /// Get the XOR-MAPPED-ADDRESS attribute (preferred reflexive address method).
    pub fn get_xor_mapped_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::XorMappedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Get the MAPPED-ADDRESS attribute (fallback reflexive address method).
    pub fn get_mapped_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::MappedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Get the reflexive address (XOR-MAPPED-ADDRESS preferred, MAPPED-ADDRESS fallback).
    pub fn get_reflexive_address(&self) -> Option<SocketAddr> {
        self.get_xor_mapped_address()
            .or_else(|| self.get_mapped_address())
    }

    /// Get the ERROR-CODE attribute if present.
    pub fn get_error_code(&self) -> Option<(u16, &str)> {
        for attr in &self.attributes {
            if let StunAttribute::ErrorCode { code, reason } = attr {
                return Some((*code, reason.as_str()));
            }
        }
        None
    }

    /// Verify the FINGERPRINT attribute (if present).
    pub fn verify_fingerprint(&self) -> bool {
        // Find the FINGERPRINT attribute position in raw bytes
        let fp_attr_size = 8; // 2 (type) + 2 (length) + 4 (value)
        if self.raw.len() < fp_attr_size {
            return false;
        }

        // Check if last 8 bytes are a FINGERPRINT attribute
        let fp_start = self.raw.len() - fp_attr_size;
        let attr_type = u16::from_be_bytes([self.raw[fp_start], self.raw[fp_start + 1]]);
        if attr_type != ATTR_FINGERPRINT {
            return false;
        }

        let stored_fp = u32::from_be_bytes([
            self.raw[fp_start + 4],
            self.raw[fp_start + 5],
            self.raw[fp_start + 6],
            self.raw[fp_start + 7],
        ]);

        // The FINGERPRINT was computed over the message with msg_len NOT including
        // the FINGERPRINT attribute (8 bytes: 2 type + 2 length + 4 value).
        // We must temporarily revert the header's msg_len before computing CRC.
        let mut buf = self.raw[..fp_start].to_vec();
        let msg_len = u16::from_be_bytes([buf[2], buf[3]]);
        if msg_len < 8 {
            return false;
        }
        let original_len = (msg_len - 8).to_be_bytes();
        buf[2] = original_len[0];
        buf[3] = original_len[1];

        let computed_fp = compute_fingerprint(&buf);
        stored_fp == computed_fp
    }

    /// Check if this is a Binding Response.
    pub fn is_binding_response(&self) -> bool {
        self.msg_type == BINDING_RESPONSE
    }

    /// Check if this is a Binding Error Response.
    pub fn is_error_response(&self) -> bool {
        self.msg_type == BINDING_ERROR_RESPONSE
    }
}

// Bring rand::RngCore into scope for fill_bytes
use rand::RngCore;

// ============================================================
// Tests
// ============================================================
