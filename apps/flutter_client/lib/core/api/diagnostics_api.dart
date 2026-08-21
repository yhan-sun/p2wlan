import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../daemon/diagnostics_auth.dart';
import '../models/diagnostics_models.dart';

class DiagnosticsApi {
  DiagnosticsApi({
    HttpClient? client,
    Future<String?> Function()? authTokenReader,
  }) : _client = client ?? HttpClient(),
       _authTokenReader = authTokenReader ?? readDiagnosticsAuthToken {
    _client.connectionTimeout = _requestTimeout;
  }

  static const _requestTimeout = Duration(milliseconds: 3500);
  // A full snapshot may briefly contend with a network handover.  Keep the
  // health probe fast, but give `/status` enough time to retry the structured
  // snapshot-timeout response instead of turning a live daemon into a network
  // error in the UI.
  static const _statusTimeout = Duration(seconds: 8);
  static const _speedTestTimeout = Duration(seconds: 45);
  // The daemon holds `/events` for up to ~25s (long-poll); give it margin.
  static const _eventsTimeout = Duration(seconds: 30);

  final HttpClient _client;
  final Future<String?> Function() _authTokenReader;

  Future<bool> fetchHealth(String diagnosticsUrl) async {
    try {
      final body = await _getText(
        _endpoint(diagnosticsUrl, '/health'),
        'text/plain',
        authorize: false,
      );
      return body.trim().isNotEmpty;
    } catch (_) {
      return false;
    }
  }

  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    final body = await _getTextWithTimeout(
      _endpoint(diagnosticsUrl, '/status'),
      'application/json',
      _statusTimeout,
    );
    final decoded = jsonDecode(body);
    if (decoded is! Map<String, dynamic>) {
      throw const DiagnosticsApiException(
        'Diagnostics endpoint /status did not return a JSON object',
      );
    }
    return StatusResponse.fromJson(decoded).snapshot;
  }

  Future<bool> requestShutdown(String diagnosticsUrl) async {
    try {
      final request = await _client
          .postUrl(_endpoint(diagnosticsUrl, '/shutdown'))
          .timeout(_requestTimeout);
      request.headers.set(HttpHeaders.acceptHeader, 'text/plain');
      await _authorize(request);
      request.headers.contentLength = 0;
      final response = await request.close().timeout(_requestTimeout);
      await response.drain<void>().timeout(_requestTimeout);
      return response.statusCode >= 200 && response.statusCode < 300;
    } catch (_) {
      return false;
    }
  }

  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) async {
    final request = await _client
        .postUrl(
          _endpoint(
            diagnosticsUrl,
            '/speedtest',
            queryParameters: {
              'peer': peerVirtualIp,
              'duration_ms': duration.inMilliseconds.toString(),
            },
          ),
        )
        .timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    await _authorize(request);
    request.headers.contentLength = 0;
    final response = await request.close().timeout(_speedTestTimeout);
    final body = await utf8.decodeStream(response).timeout(_speedTestTimeout);
    final decoded = _tryJsonObject(body);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final message = decoded?['error']?.toString();
      throw DiagnosticsApiException(
        message == null || message.isEmpty
            ? 'POST /speedtest returned HTTP ${response.statusCode}'
            : message,
      );
    }
    if (decoded == null) {
      throw const DiagnosticsApiException(
        'Diagnostics endpoint /speedtest did not return a JSON object',
      );
    }
    return SpeedTestResult.fromJson(decoded);
  }

  /// Long-poll the status event stream. Returns the current `revision` and the
  /// events with `seq > since`. Blocks up to `timeout` when no new events are
  /// available, so callers treat an empty list as "no change yet".
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    Duration timeout = _eventsTimeout,
  }) async {
    final body = await _getTextWithTimeout(
      _endpoint(
        diagnosticsUrl,
        '/events',
        queryParameters: {'since': since.toString()},
      ),
      'application/json',
      timeout,
    );
    final decoded = _tryJsonObject(body);
    if (decoded == null) {
      throw const DiagnosticsApiException(
        'Diagnostics endpoint /events did not return a JSON object',
      );
    }
    return EventsResponse.fromJson(decoded);
  }

  /// Paged peer list. `cursor` is the `node_id` to start after (omit for the
  /// first page). Returns the page plus `total` and the `next_cursor`.
  Future<PeersPageResponse> fetchPeers(
    String diagnosticsUrl, {
    String? cursor,
    int limit = 100,
  }) async {
    final params = <String, String>{'limit': limit.toString()};
    if (cursor != null) params['cursor'] = cursor;
    final body = await _getText(
      _endpoint(diagnosticsUrl, '/peers', queryParameters: params),
      'application/json',
    );
    final decoded = _tryJsonObject(body);
    if (decoded == null) {
      throw const DiagnosticsApiException(
        'Diagnostics endpoint /peers did not return a JSON object',
      );
    }
    return PeersPageResponse.fromJson(decoded);
  }

  /// Bounded tail of the daemon's own log file (last `lines`, within
  /// `maxBytes`). Returns an empty string when the daemon has no log file.
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) async {
    return _getText(
      _endpoint(
        diagnosticsUrl,
        '/logs/tail',
        queryParameters: {
          'lines': lines.toString(),
          'max_bytes': maxBytes.toString(),
        },
      ),
      'text/plain',
    );
  }

  /// Authoritative overlay-route state (read-only). Maps to the daemon's
  /// `POST /routes/verify`.
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async {
    final request = await _client
        .postUrl(_endpoint(diagnosticsUrl, '/routes/verify'))
        .timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    await _authorize(request);
    request.headers.contentLength = 0;
    final response = await request.close().timeout(_requestTimeout);
    final body = await utf8.decodeStream(response).timeout(_requestTimeout);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw DiagnosticsApiException(
        'POST /routes/verify returned HTTP ${response.statusCode}',
      );
    }
    final decoded = _tryJsonObject(body);
    if (decoded == null) {
      throw const DiagnosticsApiException(
        'Diagnostics endpoint /routes/verify did not return a JSON object',
      );
    }
    return RoutesResponse.fromJson(decoded);
  }

  /// Repair the overlay route in place (no daemon/TUN/session restart). Maps to
  /// the daemon's `POST /routes/repair`.
  Future<RouteRepairResponse> repairRoutes(String diagnosticsUrl) async {
    final request = await _client
        .postUrl(_endpoint(diagnosticsUrl, '/routes/repair'))
        .timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    await _authorize(request);
    request.headers.contentLength = 0;
    final response = await request.close().timeout(_requestTimeout);
    final body = await utf8.decodeStream(response).timeout(_requestTimeout);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw DiagnosticsApiException(
        'POST /routes/repair returned HTTP ${response.statusCode}',
      );
    }
    final decoded = _tryJsonObject(body);
    if (decoded == null) {
      throw const DiagnosticsApiException(
        'Diagnostics endpoint /routes/repair did not return a JSON object',
      );
    }
    return RouteRepairResponse.fromJson(decoded);
  }

  Future<String> _getText(
    Uri uri,
    String accept, {
    bool authorize = true,
  }) async {
    return _getTextWithTimeout(
      uri,
      accept,
      _requestTimeout,
      authorize: authorize,
    );
  }

  /// Attach the per-process diagnostics mutation token when the daemon has
  /// published one. Read fresh on every call: after a daemon restart the token
  /// is regenerated, and a stale cached value would be rejected with 403.
  Future<void> _authorize(HttpClientRequest request) async {
    final token = await _authTokenReader();
    if (token != null && token.isNotEmpty) {
      request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
    }
  }

  Future<String> _getTextWithTimeout(
    Uri uri,
    String accept,
    Duration timeout, {
    bool authorize = true,
  }) async {
    for (var attempt = 0; attempt < 2; attempt++) {
      final request = await _client.getUrl(uri).timeout(timeout);
      request.headers.set(HttpHeaders.acceptHeader, accept);
      if (authorize) await _authorize(request);
      final response = await request.close().timeout(timeout);
      final body = await utf8.decodeStream(response).timeout(timeout);
      if (authorize &&
          response.statusCode == HttpStatus.unauthorized &&
          attempt == 0) {
        // A daemon restart rotates the local session token. Re-read the file
        // once before surfacing the session-change error to the caller.
        continue;
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        final error = _tryJsonObject(body);
        final reasonCode = error?['reason_code']?.toString();
        final serverMessage = error?['error']?.toString();
        // The daemon deliberately uses a structured 503 when a complete
        // snapshot cannot be materialized before its lock budget expires.
        // Retry that condition once; it is not equivalent to /health being
        // offline.
        if (reasonCode == 'status_snapshot_timeout' && attempt == 0) {
          await Future<void>.delayed(const Duration(milliseconds: 120));
          continue;
        }
        throw DiagnosticsApiException(
          serverMessage == null || serverMessage.isEmpty
              ? 'GET ${uri.path} returned HTTP ${response.statusCode}'
              : 'GET ${uri.path} returned HTTP ${response.statusCode}: $serverMessage',
          statusCode: response.statusCode,
          reasonCode: reasonCode,
        );
      }
      return body;
    }
    throw DiagnosticsApiException('GET ${uri.path} returned HTTP 401');
  }

  Uri _endpoint(
    String diagnosticsUrl,
    String path, {
    Map<String, String>? queryParameters,
  }) {
    final parsed = Uri.parse(normalizeDiagnosticsUrl(diagnosticsUrl));
    return parsed.replace(
      path: path,
      queryParameters: queryParameters,
      fragment: null,
    );
  }

  void close() {
    _client.close(force: true);
  }
}

Map<String, dynamic>? _tryJsonObject(String body) {
  try {
    final decoded = jsonDecode(body);
    return decoded is Map<String, dynamic> ? decoded : null;
  } catch (_) {
    return null;
  }
}

class DiagnosticsApiException implements Exception {
  const DiagnosticsApiException(
    this.message, {
    this.statusCode,
    this.reasonCode,
  });

  final String message;
  final int? statusCode;
  final String? reasonCode;

  @override
  String toString() => message;
}

String normalizeDiagnosticsUrl(String value) {
  final trimmed = value.trim();
  if (trimmed.isEmpty) {
    throw const FormatException('Diagnostics URL is required');
  }
  final parsed = Uri.parse(trimmed);
  if (!parsed.hasScheme ||
      (parsed.scheme != 'http' && parsed.scheme != 'https')) {
    throw const FormatException('Diagnostics URL must use http or https');
  }
  if (parsed.host.isEmpty) {
    throw const FormatException('Diagnostics URL must include a host');
  }
  if (!_isLoopbackDiagnosticsHost(parsed.host)) {
    throw const FormatException(
      'Diagnostics URL must use localhost or a loopback address',
    );
  }
  final path = parsed.path.isEmpty || parsed.path == '/'
      ? '/status'
      : parsed.path;
  return parsed.replace(path: path, fragment: null).toString();
}

bool _isLoopbackDiagnosticsHost(String host) {
  final normalized = host.trim().toLowerCase();
  if (normalized == 'localhost' || normalized == '::1') return true;
  final address = InternetAddress.tryParse(normalized);
  return address?.isLoopback ?? false;
}
