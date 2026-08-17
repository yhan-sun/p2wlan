import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../models/diagnostics_models.dart';

class DiagnosticsApi {
  DiagnosticsApi({HttpClient? client}) : _client = client ?? HttpClient() {
    _client.connectionTimeout = _requestTimeout;
  }

  static const _requestTimeout = Duration(milliseconds: 3500);
  static const _speedTestTimeout = Duration(seconds: 45);
  // The daemon holds `/events` for up to ~25s (long-poll); give it margin.
  static const _eventsTimeout = Duration(seconds: 30);

  final HttpClient _client;

  Future<bool> fetchHealth(String diagnosticsUrl) async {
    try {
      final body = await _getText(
        _endpoint(diagnosticsUrl, '/health'),
        'text/plain',
      );
      return body.trim().isNotEmpty;
    } catch (_) {
      return false;
    }
  }

  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    final body = await _getText(
      _endpoint(diagnosticsUrl, '/status'),
      'application/json',
    );
    final decoded = jsonDecode(body);
    if (decoded is! Map<String, dynamic>) {
      throw const DiagnosticsApiException(
        'Diagnostics endpoint /status did not return a JSON object',
      );
    }
    return DiagnosticsSnapshot.fromJson(decoded);
  }

  Future<bool> requestShutdown(String diagnosticsUrl) async {
    try {
      final request = await _client
          .postUrl(_endpoint(diagnosticsUrl, '/shutdown'))
          .timeout(_requestTimeout);
      request.headers.set(HttpHeaders.acceptHeader, 'text/plain');
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
  Future<({int revision, List<Map<String, dynamic>> events})> fetchEvents(
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
    final events = [
      for (final e in _listAs(decoded['events']))
        if (e is Map<String, dynamic>) e,
    ];
    final revision = (decoded['revision'] as num?)?.toInt() ?? since;
    return (revision: revision, events: events);
  }

  /// Paged peer list. `cursor` is the `node_id` to start after (omit for the
  /// first page). Returns the page plus `total` and the `next_cursor`.
  Future<({List<Map<String, dynamic>> peers, int total, String? nextCursor})>
  fetchPeers(String diagnosticsUrl, {String? cursor, int limit = 100}) async {
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
    return (
      peers: [
        for (final p in _listAs(decoded['peers']))
          if (p is Map<String, dynamic>) p,
      ],
      total: (decoded['total'] as num?)?.toInt() ?? 0,
      nextCursor: _asStringOrNull(decoded['next_cursor']),
    );
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
  Future<Map<String, dynamic>> verifyRoutes(String diagnosticsUrl) async {
    final request = await _client
        .postUrl(_endpoint(diagnosticsUrl, '/routes/verify'))
        .timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
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
    return decoded;
  }

  /// Repair the overlay route in place (no daemon/TUN/session restart). Maps to
  /// the daemon's `POST /routes/repair`.
  Future<Map<String, dynamic>> repairRoutes(String diagnosticsUrl) async {
    final request = await _client
        .postUrl(_endpoint(diagnosticsUrl, '/routes/repair'))
        .timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
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
    return decoded;
  }

  Future<String> _getText(Uri uri, String accept) async {
    return _getTextWithTimeout(uri, accept, _requestTimeout);
  }

  Future<String> _getTextWithTimeout(
    Uri uri,
    String accept,
    Duration timeout,
  ) async {
    final request = await _client.getUrl(uri).timeout(timeout);
    request.headers.set(HttpHeaders.acceptHeader, accept);
    final response = await request.close().timeout(timeout);
    final body = await utf8.decodeStream(response).timeout(timeout);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw DiagnosticsApiException(
        'GET ${uri.path} returned HTTP ${response.statusCode}',
      );
    }
    return body;
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

List<dynamic> _listAs(dynamic value) {
  return value is List ? value : const <dynamic>[];
}

String? _asStringOrNull(dynamic value) {
  if (value == null) return null;
  return value.toString();
}

class DiagnosticsApiException implements Exception {
  const DiagnosticsApiException(this.message);

  final String message;

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
