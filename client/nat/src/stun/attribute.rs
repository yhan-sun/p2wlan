/// A STUN attribute (parsed).
#[derive(Debug, Clone)]
pub enum StunAttribute {
    /// MAPPED-ADDRESS (0x0001): the reflexive address.
    MappedAddress(SocketAddr),
    /// XOR-MAPPED-ADDRESS (0x0020): the reflexive address (XOR'd).
    XorMappedAddress(SocketAddr),
    /// CHANGE-REQUEST (0x0003): ask server to change IP/port in response.
    ChangeRequest { change_ip: bool, change_port: bool },
    /// ERROR-CODE (0x0009): error response code and reason.
    ErrorCode { code: u16, reason: String },
    /// SOFTWARE (0x8022): software description.
    Software(String),
    /// FINGERPRINT (0x8028): CRC-32 integrity check.
    Fingerprint(u32),
    /// Any other attribute we don't specifically parse.
    Other { attr_type: u16, value: Vec<u8> },
}

impl StunAttribute {
    /// Encode this attribute into (type, value) bytes.
    /// `transaction_id` is needed for XOR-MAPPED-ADDRESS encoding.
    pub fn encode(&self, transaction_id: &[u8; 12]) -> (u16, Vec<u8>) {
        match self {
            StunAttribute::MappedAddress(addr) => {
                (ATTR_MAPPED_ADDRESS, encode_mapped_address(*addr))
            }
            StunAttribute::XorMappedAddress(addr) => (
                ATTR_XOR_MAPPED_ADDRESS,
                encode_xor_mapped_address(*addr, transaction_id),
            ),
            StunAttribute::ChangeRequest {
                change_ip,
                change_port,
            } => {
                let mut flags: u32 = 0;
                if *change_ip {
                    flags |= 0x04;
                }
                if *change_port {
                    flags |= 0x02;
                }
                (ATTR_CHANGE_REQUEST, flags.to_be_bytes().to_vec())
            }
            StunAttribute::ErrorCode { code, reason } => {
                let class = (*code / 100) as u8;
                let number = (*code % 100) as u8;
                let mut buf = vec![0x00, 0x00, 0x00, class, number];
                buf.extend_from_slice(reason.as_bytes());
                (ATTR_ERROR_CODE, buf)
            }
            StunAttribute::Software(s) => (ATTR_SOFTWARE, s.as_bytes().to_vec()),
            StunAttribute::Fingerprint(val) => (ATTR_FINGERPRINT, val.to_be_bytes().to_vec()),
            StunAttribute::Other { attr_type, value } => (*attr_type, value.clone()),
        }
    }

    /// Decode an attribute from wire format.
    pub fn decode(attr_type: u16, data: &[u8], transaction_id: &[u8; 12]) -> Result<Self> {
        match attr_type {
            ATTR_MAPPED_ADDRESS => Ok(StunAttribute::MappedAddress(decode_mapped_address(data)?)),
            ATTR_XOR_MAPPED_ADDRESS => Ok(StunAttribute::XorMappedAddress(
                decode_xor_mapped_address(data, transaction_id)?,
            )),
            ATTR_CHANGE_REQUEST => {
                if data.len() < 4 {
                    return Err(NatError::InvalidAttribute(
                        "CHANGE-REQUEST too short".into(),
                    ));
                }
                let flags = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(StunAttribute::ChangeRequest {
                    change_ip: flags & 0x04 != 0,
                    change_port: flags & 0x02 != 0,
                })
            }
            ATTR_ERROR_CODE => {
                if data.len() < 5 {
                    return Err(NatError::InvalidAttribute("ERROR-CODE too short".into()));
                }
                let class = data[3] as u16;
                let number = data[4] as u16;
                let code = class * 100 + number;
                let reason = if data.len() > 5 {
                    String::from_utf8_lossy(&data[5..]).to_string()
                } else {
                    String::new()
                };
                Ok(StunAttribute::ErrorCode { code, reason })
            }
            ATTR_SOFTWARE => Ok(StunAttribute::Software(
                String::from_utf8_lossy(data).to_string(),
            )),
            ATTR_FINGERPRINT => {
                if data.len() < 4 {
                    return Err(NatError::InvalidAttribute("FINGERPRINT too short".into()));
                }
                let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(StunAttribute::Fingerprint(val))
            }
            _ => Ok(StunAttribute::Other {
                attr_type,
                value: data.to_vec(),
            }),
        }
    }
}

// ============================================================
// StunMessage
// ============================================================
