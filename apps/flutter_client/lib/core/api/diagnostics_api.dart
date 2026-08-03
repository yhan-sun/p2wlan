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
      await response.drain<void>();
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

  Future<String> _getText(Uri uri, String accept) async {
    final request = await _client.getUrl(uri).timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, accept);
    final response = await request.close().timeout(_requestTimeout);
    final body = await utf8.decodeStream(response);
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
  final path = parsed.path.isEmpty || parsed.path == '/'
      ? '/status'
      : parsed.path;
  return parsed.replace(path: path, fragment: null).toString();
}
