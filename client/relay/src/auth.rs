//! Relay ticket verification and authenticated register frame.
//!
//! ## Auth Register Frame (MSG_AUTH_REGISTER = 0x09)
//!
//! Payload layout (strict binary):
//!
//! ```text
//! u8   node_id_len         (1..255)
//! byte node_id[node_id_len] (valid UTF-8)
//! u16  ticket_len          (big-endian, 1..8192)
//! byte ticket[ticket_len]  (compact JWT)
//! ```
//!
//! ## Network binding
//!
//! The relay peer table uses `(network_id, node_id)` as the identity key.
//! Different networks never see each other. Same node_id in different
//! networks can coexist independently.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::Zeroize;

use crate::error::{RelayError, RelayErrorCode};

// ============================================================
// Constants
// ============================================================

/// New Auth Register message type.
pub const MSG_AUTH_REGISTER: u8 = 0x09;

/// Maximum ticket length (compact JWT, conservative 8 KiB upper bound).
pub const MAX_TICKET_LEN: usize = 8192;

/// Default clock skew for ticket validation.
pub const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Required JWT typ header value.
const JWT_TYP: &str = "p2wlan-relay+jwt";

/// Required issuer.
const JWT_ISSUER: &str = "p2wlan-control";

/// Relay protocol version embedded in tickets.
pub const RELAY_PROTOCOL_VERSION: u64 = 1;

// ============================================================
// Auth error codes (extend RelayErrorCode)
// ============================================================

/// Stable wire error codes for A2 authentication.
impl RelayErrorCode {
    pub const AUTH_REQUIRED: u16 = 4011;
    pub const INVALID_TICKET: u16 = 4012;
    pub const TICKET_EXPIRED: u16 = 4013;
    pub const AUDIENCE_MISMATCH: u16 = 4014;
    pub const IDENTITY_MISMATCH: u16 = 4015;
    pub const NETWORK_MISMATCH: u16 = 4016;
    pub const TICKET_NOT_YET_VALID: u16 = 4017;
    pub const UNKNOWN_TICKET_KEY: u16 = 4018;
}

// ============================================================
// Relay ticket claims (matching Go schema)
// ============================================================

/// Claims extracted from a verified relay ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTicketClaims {
    /// Must equal `sub`.
    #[serde(rename = "device_id")]
    pub device_id: String,
    /// Network the device belongs to.
    #[serde(rename = "network_id")]
    pub network_id: String,
    /// Node ID (usually equals device_id).
    #[serde(rename = "node_id")]
    pub node_id: String,
    /// Target relay region.
    #[serde(rename = "relay_region")]
    pub relay_region: String,
    /// Relay protocol version.
    #[serde(rename = "relay_protocol")]
    pub relay_protocol: u64,

    // Standard JWT fields
    #[serde(rename = "iss")]
    pub iss: String,
    #[serde(rename = "sub")]
    pub sub: String,
    #[serde(rename = "aud")]
    pub aud: serde_json::Value, // Can be string or array
    #[serde(rename = "iat")]
    pub iat: Option<i64>,
    #[serde(rename = "nbf")]
    pub nbf: Option<i64>,
    #[serde(rename = "exp")]
    pub exp: Option<i64>,
    #[serde(rename = "jti")]
    pub jti: Option<String>,
}

impl Zeroize for RelayTicketClaims {
    fn zeroize(&mut self) {
        self.device_id.zeroize();
        self.network_id.zeroize();
        self.node_id.zeroize();
    }
}

impl Drop for RelayTicketClaims {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secure wrapper that zeroizes claims on drop.
#[derive(Debug)]
pub struct VerifiedTicket {
    pub claims: RelayTicketClaims,
    pub kid: String,
}

impl Drop for VerifiedTicket {
    fn drop(&mut self) {
        self.claims.zeroize();
    }
}

// ============================================================
// Ticket verifier
// ============================================================

/// Holds the public key keyring for relay ticket verification.
pub struct TicketVerifier {
    keys: HashMap<String, VerifyingKey>,
    clock_skew: Duration,
    expected_audience: String,
    expected_region: String,
}

impl TicketVerifier {
    /// Create a new verifier.
    ///
    /// `keys`: kid -> hex-encoded Ed25519 public key (32 bytes).
    /// `clock_skew`: allowed clock skew for nbf/exp checks.
    /// `expected_audience`: the audience this relay expects.
    /// `expected_region`: the region this relay serves.
    pub fn new(
        keys: HashMap<String, String>,
        clock_skew: Duration,
        expected_audience: String,
        expected_region: String,
    ) -> std::result::Result<Self, String> {
        let mut parsed = HashMap::new();
        for (kid, hex_key) in &keys {
            let bytes = hex::decode(hex_key)
                .map_err(|e| format!("invalid hex public key for kid '{kid}': {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "public key for kid '{kid}' is {} bytes (expected 32)",
                    bytes.len()
                ));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let vk = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|e| format!("invalid Ed25519 public key for kid '{kid}': {e}"))?;
            parsed.insert(kid.clone(), vk);
        }

        if parsed.is_empty() {
            return Err("no verification keys configured".to_string());
        }

        Ok(Self {
            keys: parsed,
            clock_skew,
            expected_audience,
            expected_region,
        })
    }

    /// Verify a compact JWT ticket string and return validated claims.
    pub fn verify(&self, ticket: &str) -> std::result::Result<VerifiedTicket, RelayError> {
        // ---- Step 1: Decode header to inspect kid/alg/typ ----
        let header = decode_header(ticket).map_err(|e| {
            warn!("Failed to decode relay ticket header: {e}");
            RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                "invalid ticket header".into(),
            )
        })?;

        // Lock algorithm to EdDSA
        if header.alg != Algorithm::EdDSA {
            return Err(RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                format!("unsupported algorithm: {:?}", header.alg),
            ));
        }

        // Check typ header
        let typ = header.typ.as_deref().unwrap_or("");
        if typ != JWT_TYP {
            return Err(RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                "invalid ticket type".into(),
            ));
        }

        // Extract kid
        let kid = header.kid.as_deref().unwrap_or("").to_string();
        if kid.is_empty() {
            return Err(RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                "missing kid".into(),
            ));
        }

        // Look up the public key
        let vk = self.keys.get(&kid).ok_or_else(|| {
            RelayError::AuthError(
                RelayErrorCode::UNKNOWN_TICKET_KEY,
                format!("unknown kid: {kid}"),
            )
        })?;

        // ---- Step 2: Decode with Ed25519 verification ----
        let decoding_key = DecodingKey::from_ed_der(vk.to_bytes().as_ref());

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[JWT_ISSUER]);
        validation.set_audience(&[&self.expected_audience]);
        validation.leeway = self.clock_skew.as_secs();
        // Don't validate exp/nbf here — we'll do explicit checks with our clock skew.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        // But we must set required_spec_claims to empty, otherwise it defaults to exp
        validation.required_spec_claims = std::collections::HashSet::new();

        let token_data: TokenData<RelayTicketClaims> =
            jsonwebtoken::decode(ticket, &decoding_key, &validation).map_err(|e| {
                let code = match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        RelayErrorCode::TICKET_EXPIRED
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidSignature
                    | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => {
                        RelayErrorCode::INVALID_TICKET
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                        RelayErrorCode::AUDIENCE_MISMATCH
                    }
                    _ => RelayErrorCode::INVALID_TICKET,
                };
                warn!("Relay ticket verification failed: {e}");
                RelayError::AuthError(code, "ticket verification failed".to_string())
            })?;

        let claims = token_data.claims;

        // ---- Step 3: Explicit time checks with clock skew ----
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if let Some(exp) = claims.exp {
            if now > exp + self.clock_skew.as_secs() as i64 {
                return Err(RelayError::AuthError(
                    RelayErrorCode::TICKET_EXPIRED,
                    "ticket expired".into(),
                ));
            }
        }

        if let Some(nbf) = claims.nbf {
            if now < nbf - self.clock_skew.as_secs() as i64 {
                return Err(RelayError::AuthError(
                    RelayErrorCode::TICKET_NOT_YET_VALID,
                    "ticket not yet valid".into(),
                ));
            }
        }

        // ---- Step 4: Claim-level validation ----
        if claims.device_id.is_empty() {
            return Err(RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                "missing device_id".into(),
            ));
        }
        if claims.network_id.is_empty() {
            return Err(RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                "missing network_id".into(),
            ));
        }
        if claims.node_id.is_empty() {
            return Err(RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                "missing node_id".into(),
            ));
        }
        if claims.sub != claims.device_id {
            return Err(RelayError::AuthError(
                RelayErrorCode::IDENTITY_MISMATCH,
                "sub does not match device_id".into(),
            ));
        }
        // Audience must be a single string matching expected_audience
        let aud_str = match &claims.aud {
            serde_json::Value::String(s) if !s.is_empty() => s.clone(),
            serde_json::Value::Array(arr) => {
                return Err(RelayError::AuthError(
                    RelayErrorCode::AUDIENCE_MISMATCH,
                    format!(
                        "audience must be a single string, got array of {} elements",
                        arr.len()
                    ),
                ));
            }
            _ => {
                return Err(RelayError::AuthError(
                    RelayErrorCode::AUDIENCE_MISMATCH,
                    "audience is missing or empty".into(),
                ));
            }
        };
        if aud_str != self.expected_audience {
            return Err(RelayError::AuthError(
                RelayErrorCode::AUDIENCE_MISMATCH,
                format!(
                    "ticket audience '{}' does not match expected '{}'",
                    aud_str, self.expected_audience
                ),
            ));
        }
        if claims.relay_region != self.expected_region {
            return Err(RelayError::AuthError(
                RelayErrorCode::AUDIENCE_MISMATCH,
                format!(
                    "ticket region '{}' does not match this relay '{}'",
                    claims.relay_region, self.expected_region
                ),
            ));
        }
        if claims.relay_protocol != RELAY_PROTOCOL_VERSION {
            return Err(RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                "unsupported relay protocol version".into(),
            ));
        }
        if claims.iss != JWT_ISSUER {
            return Err(RelayError::AuthError(
                RelayErrorCode::INVALID_TICKET,
                "invalid issuer".into(),
            ));
        }

        Ok(VerifiedTicket { claims, kid })
    }

    /// Number of public keys in the keyring.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

// ============================================================
// Auth Register frame encode/decode
// ============================================================

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

/// Identity key for the relay peer table: `(network_id, node_id)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkNodeKey {
    pub network_id: String,
    pub node_id: String,
}

impl NetworkNodeKey {
    pub fn new(network_id: String, node_id: String) -> Self {
        Self {
            network_id,
            node_id,
        }
    }
}

impl std::fmt::Display for NetworkNodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network_id, self.node_id)
    }
}

/// Authenticated peer context stored alongside each connection.
#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub network_id: String,
    pub device_id: String,
    pub node_id: String,
    pub audience: String,
    pub region: String,
    pub ticket_expiry: Option<i64>,
    pub kid: String,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{EncodingKey, Header};
    use rand::rngs::OsRng;
    use rand::RngCore;

    /// Generate a test Ed25519 key pair and return (kid, private_key_hex, public_key_hex).
    fn generate_test_key(kid: &str) -> (String, String, String) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let private_hex = hex::encode(signing_key.to_bytes());
        let public_hex = hex::encode(verifying_key.to_bytes());
        (kid.to_string(), private_hex, public_hex)
    }

    /// Sign a set of claims with the given key and kid.
    fn sign_test_ticket(claims: &RelayTicketClaims, kid: &str, private_key_hex: &str) -> String {
        let private_bytes = hex::decode(private_key_hex).unwrap();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Encode to PKCS#8 DER format required by jsonwebtoken
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let der = signing_key.to_pkcs8_der().unwrap();

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        header.typ = Some(JWT_TYP.to_string());

        let encoding_key = EncodingKey::from_ed_der(der.as_bytes());
        jsonwebtoken::encode(&header, claims, &encoding_key).unwrap()
    }

    fn make_test_claims(audience: &str, region: &str) -> RelayTicketClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        RelayTicketClaims {
            device_id: "test-device".into(),
            network_id: "default".into(),
            node_id: "test-device".into(),
            relay_region: region.into(),
            relay_protocol: RELAY_PROTOCOL_VERSION,
            iss: JWT_ISSUER.into(),
            sub: "test-device".into(),
            aud: serde_json::Value::String(audience.into()),
            iat: Some(now),
            nbf: Some(now - 1),
            exp: Some(now + 300),
            jti: Some(hex::encode(rand::random::<[u8; 16]>())),
        }
    }

    #[test]
    fn test_auth_register_encode_decode_roundtrip() {
        let node_id = "my-node-123";
        let ticket = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.signature";

        let encoded = encode_auth_register(node_id, ticket).unwrap();
        let (decoded_node, decoded_ticket) = decode_auth_register(&encoded).unwrap();

        assert_eq!(decoded_node, node_id);
        assert_eq!(decoded_ticket, ticket);
    }

    #[test]
    fn test_auth_register_encode_decode_golden_vector() {
        // Golden vector for cross-language testing
        let node_id = "node-golden";
        let ticket = "test-jwt-token-value";
        let ticket_len = ticket.len(); // 20

        let encoded = encode_auth_register(node_id, ticket).unwrap();

        // Manual verification of the binary layout
        assert_eq!(encoded[0], 11); // node_id_len = "node-golden".len() = 11
        assert_eq!(&encoded[1..12], b"node-golden"); // node_id bytes
        assert_eq!(
            u16::from_be_bytes([encoded[12], encoded[13]]) as usize,
            ticket_len
        );
        assert_eq!(&encoded[14..], ticket.as_bytes()); // ticket bytes
    }

    #[test]
    fn test_auth_register_rejects_truncated() {
        let node_id = "node";
        let ticket = "ticket";
        let encoded = encode_auth_register(node_id, ticket).unwrap();

        // Truncate various amounts and verify they all fail
        for trim in 1..encoded.len() {
            assert!(
                decode_auth_register(&encoded[..trim]).is_err(),
                "should fail with {trim} bytes"
            );
        }
    }

    #[test]
    fn test_auth_register_rejects_trailing_bytes() {
        let node_id = "node";
        let ticket = "ticket";
        let mut encoded = encode_auth_register(node_id, ticket).unwrap();
        encoded.push(0x00); // trailing byte

        assert!(decode_auth_register(&encoded).is_err());
    }

    #[test]
    fn test_auth_register_rejects_empty_ticket() {
        assert!(encode_auth_register("node", "").is_err());
    }

    #[test]
    fn test_auth_register_rejects_oversized_ticket() {
        let big_ticket = "x".repeat(MAX_TICKET_LEN + 1);
        assert!(encode_auth_register("node", &big_ticket).is_err());
    }

    #[test]
    fn test_auth_register_rejects_invalid_utf8_node_id() {
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        // Direct binary construction with invalid UTF-8
        let mut payload = Vec::new();
        payload.push(invalid_utf8.len() as u8);
        payload.extend_from_slice(&invalid_utf8);
        payload.extend_from_slice(&6u16.to_be_bytes());
        payload.extend_from_slice(b"ticket");

        assert!(decode_auth_register(&payload).is_err());
    }

    #[test]
    fn test_ticket_verify_valid() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");

        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let verified = verifier.verify(&ticket).unwrap();
        assert_eq!(verified.claims.device_id, "test-device");
        assert_eq!(verified.claims.network_id, "default");
        assert_eq!(verified.kid, "key-1");
    }

    #[test]
    fn test_ticket_verify_rejects_wrong_algorithm() {
        // A token with HS256 algorithm should be rejected
        let ticket = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid";
        let (kid, _priv, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid, pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        // Should fail because algorithm is not EdDSA
        let result = verifier.verify(ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_unknown_kid() {
        let (kid, priv_hex, _pub_hex) = generate_test_key("key-1");
        let (_kid2, _priv2, pub_hex2) = generate_test_key("key-2");

        let mut keys = HashMap::new();
        keys.insert("key-2".to_string(), pub_hex2); // different kid than signer

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex); // signed with key-1

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
        match result {
            Err(RelayError::AuthError(code, _)) => {
                assert_eq!(code, RelayErrorCode::UNKNOWN_TICKET_KEY);
            }
            other => panic!("expected AuthError(UNKNOWN_TICKET_KEY), got: {other:?}"),
        }
    }

    #[test]
    fn test_ticket_verify_rejects_wrong_audience() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        // Verifier expects "relay-us-1" but ticket is for "relay-sg-1"
        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-us-1".into(), "us".into())
                .unwrap();

        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_wrong_region() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "us".into())
                .unwrap();

        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_array_audience() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let mut claims = make_test_claims("relay-sg-1", "sg");
        claims.aud = serde_json::json!(["aud-1", "aud-2"]);
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        match result {
            Err(RelayError::AuthError(code, _)) => {
                assert_eq!(code, RelayErrorCode::AUDIENCE_MISMATCH);
            }
            other => panic!("expected AUDIENCE_MISMATCH for array audience, got: {other:?}"),
        }
    }

    #[test]
    fn test_ticket_verify_rejects_empty_audience() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let mut claims = make_test_claims("relay-sg-1", "sg");
        claims.aud = serde_json::Value::String(String::new());
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_expired() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let mut claims = make_test_claims("relay-sg-1", "sg");
        // Set expiry in the past
        claims.exp = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 3600,
        );
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_identity_mismatch() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let mut claims = make_test_claims("relay-sg-1", "sg");
        claims.sub = "different-device".to_string(); // doesn't match device_id
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation_current_and_previous() {
        let (kid_curr, priv_curr, pub_curr) = generate_test_key("key-2");
        let (kid_prev, priv_prev, pub_prev) = generate_test_key("key-1");

        let mut keys = HashMap::new();
        keys.insert(kid_curr.clone(), pub_curr);
        keys.insert(kid_prev.clone(), pub_prev);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        // Ticket signed with current key works
        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid_curr, &priv_curr);
        assert!(verifier.verify(&ticket).is_ok());

        // Ticket signed with previous key works
        let claims2 = make_test_claims("relay-sg-1", "sg");
        let ticket2 = sign_test_ticket(&claims2, &kid_prev, &priv_prev);
        assert!(verifier.verify(&ticket2).is_ok());

        // Unknown key fails
        let (kid_unknown, priv_unknown, _) = generate_test_key("key-unknown");
        let claims3 = make_test_claims("relay-sg-1", "sg");
        let ticket3 = sign_test_ticket(&claims3, &kid_unknown, &priv_unknown);
        assert!(verifier.verify(&ticket3).is_err());
    }

    #[test]
    fn test_network_node_key() {
        let k1 = NetworkNodeKey::new("net-a".into(), "node-1".into());
        let k2 = NetworkNodeKey::new("net-a".into(), "node-2".into());
        let k3 = NetworkNodeKey::new("net-b".into(), "node-1".into());
        let k4 = NetworkNodeKey::new("net-a".into(), "node-1".into());

        assert_eq!(k1, k4);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k2, k3);

        let mut map = HashMap::new();
        map.insert(k1.clone(), 1);
        map.insert(k2.clone(), 2);
        map.insert(k3.clone(), 3);

        assert_eq!(map.get(&k1), Some(&1));
        assert_eq!(map.get(&k4), Some(&1)); // same key
        assert_eq!(
            map.get(&NetworkNodeKey::new("net-b".into(), "node-1".into())),
            Some(&3)
        );
    }

    #[test]
    fn test_ticket_verifier_rejects_empty_keyring() {
        let result = TicketVerifier::new(
            HashMap::new(),
            DEFAULT_CLOCK_SKEW,
            "relay-sg-1".into(),
            "sg".into(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_error_codes() {
        // Verify new A2 error codes are distinct and in expected range
        let codes = [
            RelayErrorCode::AUTH_REQUIRED,
            RelayErrorCode::INVALID_TICKET,
            RelayErrorCode::TICKET_EXPIRED,
            RelayErrorCode::AUDIENCE_MISMATCH,
            RelayErrorCode::IDENTITY_MISMATCH,
            RelayErrorCode::NETWORK_MISMATCH,
            RelayErrorCode::TICKET_NOT_YET_VALID,
            RelayErrorCode::UNKNOWN_TICKET_KEY,
        ];

        let mut seen = std::collections::HashSet::new();
        for &code in &codes {
            assert!(seen.insert(code), "duplicate error code: {code}");
            assert!(
                (4011..=4018).contains(&code),
                "error code {code} outside expected range 4011-4018"
            );
        }
    }
}
