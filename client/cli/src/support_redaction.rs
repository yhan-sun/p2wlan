//! Last-resort sanitization for support logs and status text. Keep credentials
//! out of diagnostics at the source; field names cannot detect arbitrary
//! business data or unlabeled secrets.

const SECRET_FIELDS: &[&str] = &[
    "authorization",
    "token",
    "auth_token",
    "authtoken",
    "device_credential",
    "invite_token",
    "invite",
    "private_key",
    "ed25519_private_key",
    "password",
    "secret",
    "jwt_secret",
    "control_admin_token",
    "relay_ticket",
    "ticket",
    "access_token",
    "access-token",
    "refresh_token",
    "refresh-token",
    "jwt",
    "api_key",
    "api-key",
    "apikey",
    "cookie",
    "set-cookie",
    "session",
];

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_STRING_LAYERS: usize = 8;

pub(crate) fn redact_support_text(input: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(input) {
        redact_json_value(&mut value, 0, 0);
        return serde_json::to_string(&value).unwrap_or_else(|_| "\"<redacted>\"".into());
    }
    redact_plain_text(input)
}

fn redact_json_value(value: &mut serde_json::Value, depth: usize, string_layers: usize) {
    if depth >= MAX_JSON_DEPTH {
        *value = serde_json::Value::String("<redacted>".into());
        return;
    }
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                if SECRET_FIELDS
                    .iter()
                    .any(|field| name.eq_ignore_ascii_case(field))
                {
                    *value = serde_json::Value::String("<redacted>".into());
                } else {
                    redact_json_value(value, depth + 1, string_layers);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json_value(value, depth + 1, string_layers);
            }
        }
        serde_json::Value::String(text) => {
            if string_layers >= MAX_JSON_STRING_LAYERS {
                *text = "<redacted>".into();
            } else if let Ok(mut nested) = serde_json::from_str::<serde_json::Value>(text) {
                redact_json_value(&mut nested, depth + 1, string_layers + 1);
                *text = serde_json::to_string(&nested).unwrap_or_else(|_| "<redacted>".into());
            } else {
                *text = redact_plain_text(text);
            }
        }
        _ => {}
    }
}

fn redact_plain_text(input: &str) -> String {
    let mut output = redact_private_key_blocks(input);
    output = redact_escaped_credential_lines(&output);
    for field in SECRET_FIELDS {
        output = redact_field(&output, field);
    }
    redact_field(&output, "bearer")
}

fn escaped_quote_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut offset = start;
    while bytes.get(offset) == Some(&b'\\') {
        offset += 1;
    }
    (offset > start && matches!(bytes.get(offset), Some(b'"' | b'\''))).then_some(offset + 1)
}

fn has_escaped_credential(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let bytes = line.as_bytes();
    for field in SECRET_FIELDS
        .iter()
        .copied()
        .chain(std::iter::once("bearer"))
    {
        for (start, _) in lower.match_indices(field) {
            let end = start + field.len();
            if (start > 0 && is_name_byte(bytes[start - 1]))
                || bytes.get(end).is_some_and(|byte| is_name_byte(*byte))
            {
                continue;
            }
            let mut offset = end;
            let mut escaped_name = false;
            if let Some(end) = escaped_quote_end(bytes, offset) {
                offset = end;
                escaped_name = true;
            } else if matches!(bytes.get(offset), Some(b'"' | b'\'')) {
                offset += 1;
            }
            let whitespace_start = offset;
            offset = skip_whitespace(line, offset);
            if field == "bearer" {
                if offset == whitespace_start {
                    continue;
                }
            } else {
                if !matches!(bytes.get(offset), Some(b':' | b'=')) {
                    continue;
                }
                offset = skip_whitespace(line, offset + 1);
            }
            if escaped_name || escaped_quote_end(bytes, offset).is_some() {
                return true;
            }
        }
    }
    false
}

fn redact_escaped_credential_lines(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        if has_escaped_credential(line) {
            // Mixed log text has no reliable JSON-string boundary. Remove the
            // whole affected line rather than retaining a partial credential.
            output.push_str("<redacted>");
            if line.ends_with("\r\n") {
                output.push_str("\r\n");
            } else if line.ends_with('\n') {
                output.push('\n');
            }
        } else {
            output.push_str(line);
        }
    }
    output
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn skip_whitespace(input: &str, offset: usize) -> usize {
    input[offset..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map_or(input.len(), |(index, _)| offset + index)
}

fn redact_field(input: &str, field: &str) -> String {
    // ASCII case folding preserves byte offsets, including in UTF-8 logs.
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(relative) = lower[search..].find(field) {
        let start = search + relative;
        let end = start + field.len();
        search = end;
        if (start > 0 && is_name_byte(bytes[start - 1]))
            || bytes.get(end).is_some_and(|byte| is_name_byte(*byte))
        {
            continue;
        }
        let mut value_start = end;
        if field == "bearer" {
            value_start = skip_whitespace(input, value_start);
            if value_start == end {
                continue;
            }
        } else {
            if matches!(bytes.get(value_start), Some(b'"' | b'\'')) {
                value_start += 1;
            }
            value_start = skip_whitespace(input, value_start);
            if !matches!(bytes.get(value_start), Some(b':' | b'=')) {
                continue;
            }
            value_start = skip_whitespace(input, value_start + 1);
        }
        // Header values can contain multiple credentials separated by commas
        // or semicolons. A structured JSON document was handled above; in
        // plain log text conservatively remove the remaining header line.
        let whole_line = matches!(field, "authorization" | "cookie" | "set-cookie")
            || matches!(bytes.get(value_start), Some(b'{' | b'['));
        let quote = bytes
            .get(value_start)
            .copied()
            .filter(|b| !whole_line && matches!(b, b'"' | b'\''));
        if quote.is_some() {
            value_start += 1;
        }
        let mut value_end = value_start;
        let mut escaped = false;
        for (index, ch) in input[value_start..].char_indices() {
            if let Some(quote) = quote {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == char::from(quote) {
                    break;
                }
            } else if matches!(ch, '\r' | '\n')
                || (!whole_line
                    && (matches!(ch, ',' | ';' | '"' | '\'' | '}' | ']' | ')')
                        || ch.is_whitespace()))
            {
                break;
            }
            value_end = value_start + index + ch.len_utf8();
        }
        output.push_str(&input[copied..value_start]);
        if value_end > value_start {
            output.push_str("<redacted>");
        }
        copied = value_end;
        search = value_end;
    }
    output.push_str(&input[copied..]);
    output
}

fn redact_private_key_blocks(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(relative) = lower[search..].find("-----begin ") {
        let start = search + relative;
        let label_start = start + "-----begin ".len();
        let Some(label_end) = lower[label_start..].find("-----").map(|i| label_start + i) else {
            break;
        };
        search = label_end + 5;
        let label = &lower[label_start..label_end];
        if !label.ends_with("private key") && label != "pgp private key block" {
            continue;
        }
        let footer = format!("-----end {label}-----");
        let value_end = lower[search..]
            .find(&footer)
            .map_or(input.len(), |i| search + i);
        output.push_str(&input[copied..search]);
        output.push_str("<redacted>");
        copied = value_end;
        search = value_end;
    }
    output.push_str(&input[copied..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_all_cookie_header_values() {
        for header in ["Cookie", "Set-Cookie"] {
            let input = format!(
                "{header}: sessionid=synthetic-secret; csrftoken=synthetic-secret\npeer=online"
            );
            let output = redact_support_text(&input);
            assert!(!output.contains("synthetic-secret"));
            assert!(output.ends_with("\npeer=online"));
        }
    }

    #[test]
    fn redacts_structured_values_and_decoded_json_field_names() {
        let input = r#"{"secret":{"seed":"synthetic-secret"},"private\u005fkey":"synthetic-secret","peer_count":2}"#;
        let output = redact_support_text(input);
        assert!(!output.contains("synthetic-secret"));
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["secret"], "<redacted>");
        assert_eq!(value["private_key"], "<redacted>");
        assert_eq!(value["peer_count"], 2);
    }

    #[test]
    fn redacts_nested_json_strings_and_escaped_log_lines() {
        let nested = serde_json::json!({"response": r#"{"private_key":"synthetic-secret"}"#});
        assert!(!redact_support_text(&nested.to_string()).contains("synthetic-secret"));
        for input in [
            r#"response="{\"private_key\":\"synthetic-secret\"}""#,
            r#"token=\"synthetic-secret\""#,
        ] {
            let output = redact_support_text(&format!("{input}\npeer=online"));
            assert!(!output.contains("synthetic-secret"));
            assert!(output.ends_with("\npeer=online"));
        }
    }

    #[test]
    fn redacts_pgp_private_key_armor() {
        let input = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-secret\n-----END PGP PRIVATE KEY BLOCK-----\npeer=online";
        let output = redact_support_text(input);
        assert!(!output.contains("synthetic-secret"));
        assert!(output.ends_with("\npeer=online"));
    }

    #[test]
    fn masks_values_beyond_json_redaction_depth_budgets() {
        let mut encoded = r#"{"private_key":"synthetic-secret"}"#.to_string();
        for _ in 0..=MAX_JSON_STRING_LAYERS {
            encoded = serde_json::to_string(&encoded).unwrap();
        }
        let output = redact_support_text(&encoded);
        assert!(!output.contains("synthetic-secret"));
        assert_eq!(redact_support_text(&output), output);

        let mut nested = serde_json::json!({"private_key": "synthetic-secret"});
        for _ in 0..=MAX_JSON_DEPTH {
            nested = serde_json::json!({"level": nested});
        }
        let output = redact_support_text(&nested.to_string());
        assert!(!output.contains("synthetic-secret"));
        assert!(serde_json::from_str::<serde_json::Value>(&output).is_ok());
    }

    #[test]
    fn incomplete_structured_credentials_are_masked_to_line_end() {
        let output = redact_support_text(
            "secret={seed:synthetic-secret};other=synthetic-secret\npeer=online",
        );
        assert!(!output.contains("synthetic-secret"));
        assert!(output.ends_with("\npeer=online"));
    }

    #[test]
    fn redacts_compact_json_and_preserves_structure() {
        let input = r#"{"private_key":"key-secret","nested":{"auth_token" : "jwt-secret","relay_ticket":"ticket-secret"},"peer_count":2}"#;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&redact_support_text(input)).unwrap(),
            serde_json::json!({
                "private_key": "<redacted>",
                "nested": {"auth_token": "<redacted>", "relay_ticket": "<redacted>"},
                "peer_count": 2,
            })
        );
    }

    #[test]
    fn redacts_whitespace_quotes_and_escaped_quotes() {
        let input = r#"password: secret-one private_key="secret two" ED25519_PRIVATE_KEY = 'secret three' token="escaped\"still-secret" device_credential='秘密'"#;
        let output = redact_support_text(input);
        assert!(!output.contains("secret"));
        assert!(!output.contains("秘密"));
        assert_eq!(output.matches("<redacted>").count(), 5);
    }

    #[test]
    fn redacts_complete_authorization_and_standalone_bearer_values() {
        assert_eq!(
            redact_support_text("Authorization: Basic user:password\npeer=online"),
            "Authorization: <redacted>\npeer=online"
        );
        assert_eq!(
            redact_support_text("bearer\tjwt-secret"),
            "bearer\t<redacted>"
        );
    }

    #[test]
    fn redacts_truncated_strings_and_private_key_blocks() {
        assert_eq!(
            redact_support_text(r#"token="unterminated\"secret"#),
            r#"token="<redacted>"#
        );
        let pem = "before\n-----BEGIN PRIVATE KEY-----\nsecret-key-body\n-----END PRIVATE KEY-----\nafter";
        let output = redact_support_text(pem);
        assert!(!output.contains("secret-key-body"));
        assert!(output.ends_with("\nafter"));
        assert_eq!(
            redact_support_text("-----BEGIN RSA PRIVATE KEY-----\ntruncated-body"),
            "-----BEGIN RSA PRIVATE KEY-----<redacted>"
        );
    }

    #[test]
    fn preserves_nonsecret_diagnostics_and_is_idempotent() {
        let diagnostic =
            "节点在线 peer_count=2 token_count=3 token rotation scheduled public_key=abc";
        assert_eq!(redact_support_text(diagnostic), diagnostic);
        let redacted = redact_support_text("token=secret; password='other secret'");
        assert_eq!(redact_support_text(&redacted), redacted);
    }
}
