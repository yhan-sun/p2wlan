// Redaction boundary for any text that may leave the process in a form a user
// or a third party can read: diagnostic log tails, raw JSON blobs, and support
// bundles. These surfaces must never carry live credentials.
//
// This is a conservative, string-level sanitizer. It does NOT replace keeping
// secrets out of these streams in the first place — it is the last line of
// defense so an accidental inclusion is not exfiltrated.

/// Replace values that look like credentials with a fixed mask.
///
/// Coverage:
///  - PEM private-key blocks (whole body masked);
///  - `Bearer <token>` (the standard Authorization header value);
///  - `key : "value"` / `key = 'value'` (quoted, e.g. JSON) — value masked,
///    quotes and key preserved;
///  - `key: value` / `key=value` (bare single-token, e.g. `token=abc`).
/// Keys are matched case-insensitively from a curated credential-bearing list.
String redactSensitive(String input) {
  if (input.isEmpty) return input;
  var result = input;

  // 1. PEM private-key blocks: mask the body, keep the (anonymized) header.
  result = _mapMatches(
    result,
    RegExp(
      r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----',
      caseSensitive: false,
    ),
    (_) => '-----BEGIN ***PRIVATE KEY***-----<redacted>-----END ***PRIVATE KEY***-----',
  );

  // 2. Bearer tokens: `Bearer abc.def-123` -> `Bearer <redacted>`.
  result = _mapMatches(
    result,
    RegExp(r'Bearer\s+[A-Za-z0-9._\-]+', caseSensitive: false),
    (_) => 'Bearer <redacted>',
  );

  // Quoted form: key : "value" / key = 'value'.
  const quotedKeys = <String>[
    'authorization',
    'token',
    'authtoken',
    'relay_ticket',
    'ticket',
    'session',
    'cookie',
    'api_key',
    'apikey',
    'secret',
    'password',
    'private_key',
    'device_credential',
    'access_token',
    'refresh_token',
    'jwt',
  ];
  result = _mapMatches(
    result,
    RegExp(
      "(['\"]?(${quotedKeys.join('|')})['\"]?\\s*[:=]\\s*)(['\"])([^'\"]*)(['\"])",
      caseSensitive: false,
    ),
    (m) => '${m[1]}${m[3]}<redacted>${m[3]}',
  );

  // Bare single-token form: key: value / key=value. `authorization` is excluded
  // here because its real value is the multi-word `Bearer <tok>` handled above
  // (and its quoted JSON form is handled by the quoted rule); masking only its
  // first token would leave the actual credential intact.
  const bareKeys = <String>[
    'token',
    'authtoken',
    'relay_ticket',
    'ticket',
    'session',
    'cookie',
    'api_key',
    'apikey',
    'secret',
    'password',
    'private_key',
    'device_credential',
    'access_token',
    'refresh_token',
    'jwt',
  ];
  result = _mapMatches(
    result,
    RegExp(
      "(['\"]?(${bareKeys.join('|')})['\"]?\\s*[:=]\\s*)([^\\s'\",;{}\\]]+)",
      caseSensitive: false,
    ),
    (m) {
      final full = m[0] ?? '';
      return full.contains('<redacted>') ? full : '${m[1]}<redacted>';
    },
  );

  return result;
}

/// Rebuild [input] by replacing every match of [re] with [f](match), using
/// `allMatches` to avoid `String.replaceAll`'s overload ambiguity.
String _mapMatches(String input, RegExp re, String Function(RegExpMatch) f) {
  final sb = StringBuffer();
  var last = 0;
  for (final m in re.allMatches(input)) {
    sb.write(input.substring(last, m.start));
    sb.write(f(m));
    last = m.end;
  }
  sb.write(input.substring(last));
  return sb.toString();
}

/// Convenience: redact every line and join, for log-tail display.
String redactLines(Iterable<String> lines) {
  return lines.map(redactSensitive).join('\n');
}
