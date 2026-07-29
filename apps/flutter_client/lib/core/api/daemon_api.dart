import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../models/daemon_models.dart';

class DaemonApi {
  DaemonApi({HttpClient? client}) : _client = client ?? HttpClient() {
    _client.connectionTimeout = _requestTimeout;
  }

  static const _requestTimeout = Duration(milliseconds: 3500);

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

  Future<DaemonSnapshot> fetchStatus(String diagnosticsUrl) async {
    final body = await _getText(
      _endpoint(diagnosticsUrl, '/status'),
      'application/json',
    );
    final decoded = jsonDecode(body);
    if (decoded is! Map<String, dynamic>) {
      throw const DaemonApiException(
        'Daemon /status did not return a JSON object',
      );
    }
    return DaemonSnapshot.fromJson(decoded);
  }

  Future<String> _getText(Uri uri, String accept) async {
    final request = await _client.getUrl(uri).timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, accept);
    final response = await request.close().timeout(_requestTimeout);
    final body = await utf8.decodeStream(response);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw DaemonApiException(
        'GET ${uri.path} returned HTTP ${response.statusCode}',
      );
    }
    return body;
  }

  Uri _endpoint(String diagnosticsUrl, String path) {
    final parsed = Uri.parse(normalizeDiagnosticsUrl(diagnosticsUrl));
    return parsed.replace(path: path, query: null, fragment: null);
  }

  void close() {
    _client.close(force: true);
  }
}

class DaemonApiException implements Exception {
  const DaemonApiException(this.message);

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
