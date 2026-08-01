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
