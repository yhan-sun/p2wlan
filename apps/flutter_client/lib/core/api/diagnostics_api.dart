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
    _client
      ..connectionTimeout = _requestTimeout
      ..findProxy = null;
  }

  static const _requestTimeout = Duration(milliseconds: 3500);
  static const _statusTimeout = Duration(seconds: 8);
  static const _speedTestTimeout = Duration(seconds: 45);
  static const _eventsTimeout = Duration(seconds: 30);
  static const _authRetryDelays = [
    Duration(milliseconds: 100),
    Duration(milliseconds: 200),
    Duration(milliseconds: 400),
  ];

  final HttpClient _client;
  final Future<String?> Function() _authTokenReader;
  final _healthFailures = <String, DiagnosticsApiException>{};
  HttpClientRequest? _speedTestRequest;
  Completer<void>? _speedTestCancellation;
  var _speedTestGeneration = 0;

  DiagnosticsApiException? healthFailureFor(String diagnosticsUrl) =>
      _healthFailures[diagnosticsUrl];

  Future<bool> fetchHealth(String diagnosticsUrl) async {
    try {
      final body = await _getText(
        _endpoint(diagnosticsUrl, '/health'),
        'text/plain',
        authorize: false,
      ).timeout(_requestTimeout);
      if (body.trim() != 'ok') {
        throw const DiagnosticsApiException(
          'GET /health returned an unexpected response',
          reasonCode: 'health_invalid_response',
        );
      }
      _healthFailures.remove(diagnosticsUrl);
      return true;
    } catch (error) {
      final failure = switch (error) {
        TimeoutException() => const DiagnosticsApiException(
          'GET /health timed out while waiting for the local service',
          reasonCode: 'health_timeout',
        ),
        SocketException() => const DiagnosticsApiException(
          'GET /health could not connect to the local service',
          reasonCode: 'health_connection_failed',
        ),
        DiagnosticsApiException() => error,
        FormatException() => const DiagnosticsApiException(
          'The local diagnostics address is invalid',
          reasonCode: 'health_invalid_address',
        ),
        _ => const DiagnosticsApiException(
          'GET /health failed while reading the local service response',
          reasonCode: 'health_read_failed',
        ),
      };
      if (_healthFailures.length >= 8) _healthFailures.clear();
      _healthFailures[diagnosticsUrl] = failure;
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
      final response = await _closeRequest(request, _requestTimeout);
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
    if (_speedTestCancellation != null) {
      throw const DiagnosticsApiException(
        'A speed test is already running',
        reasonCode: 'speedtest_busy',
      );
    }
    final generation = ++_speedTestGeneration;
    final cancellation = Completer<void>();
    _speedTestCancellation = cancellation;
    HttpClientRequest? activeRequest;
    void verifySession() {
      if (generation != _speedTestGeneration) {
        activeRequest?.abort();
        throw const DiagnosticsApiException(
          'Speed test cancelled',
          reasonCode: 'speedtest_cancelled',
        );
      }
    }

    Future<SpeedTestResult> perform() async {
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
      activeRequest = request;
      verifySession();
      _speedTestRequest = request;
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      await _authorize(request).timeout(_requestTimeout);
      verifySession();
      request.headers.contentLength = 0;
      final response = await _closeRequest(request, _speedTestTimeout);
      final body = await utf8.decodeStream(response).timeout(_speedTestTimeout);
      verifySession();
      final decoded = _tryJsonObject(body);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        final message = decoded?['error']?.toString();
        throw DiagnosticsApiException(
          message == null || message.isEmpty
              ? 'POST /speedtest returned HTTP ${response.statusCode}'
              : message,
          statusCode: response.statusCode,
          reasonCode: decoded?['reason_code']?.toString(),
        );
      }
      if (decoded == null) {
        throw const DiagnosticsApiException(
          'Diagnostics endpoint /speedtest did not return a JSON object',
        );
      }
      return SpeedTestResult.fromJson(decoded);
    }

    try {
      return await Future.any<SpeedTestResult>([
        perform(),
        cancellation.future.then<SpeedTestResult>((_) {
          throw const DiagnosticsApiException(
            'Speed test cancelled',
            reasonCode: 'speedtest_cancelled',
          );
        }),
      ]).timeout(_speedTestTimeout);
    } catch (_) {
      activeRequest?.abort();
      if (generation != _speedTestGeneration) {
        throw const DiagnosticsApiException(
          'Speed test cancelled',
          reasonCode: 'speedtest_cancelled',
        );
      }
      rethrow;
    } finally {
      if (generation == _speedTestGeneration) {
        _speedTestGeneration += 1;
        _speedTestRequest = null;
        _speedTestCancellation = null;
      }
    }
  }

  void cancelSpeedTest() {
    _speedTestGeneration += 1;
    final cancellation = _speedTestCancellation;
    _speedTestCancellation = null;
    _speedTestRequest?.abort();
    _speedTestRequest = null;
    if (cancellation != null && !cancellation.isCompleted) {
      cancellation.complete();
    }
  }

  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    int? processId,
    Duration timeout = _eventsTimeout,
  }) async {
    final query = <String, String>{'since': since.toString()};
    if (processId != null) query['process_id'] = processId.toString();
    final body = await _getTextWithTimeout(
      _endpoint(diagnosticsUrl, '/events', queryParameters: query),
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

  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async {
    final request = await _client
        .postUrl(_endpoint(diagnosticsUrl, '/routes/verify'))
        .timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    await _authorize(request);
    request.headers.contentLength = 0;
    final response = await _closeRequest(request, _requestTimeout);
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

  Future<RouteRepairResponse> repairRoutes(String diagnosticsUrl) async {
    final request = await _client
        .postUrl(_endpoint(diagnosticsUrl, '/routes/repair'))
        .timeout(_requestTimeout);
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    await _authorize(request);
    request.headers.contentLength = 0;
    final response = await _closeRequest(request, _requestTimeout);
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
    for (var attempt = 0; attempt <= _authRetryDelays.length; attempt++) {
      final request = await _client.getUrl(uri).timeout(timeout);
      request.headers.set(HttpHeaders.acceptHeader, accept);
      HttpClientResponse response;
      String body;
      try {
        if (authorize) await _authorize(request).timeout(timeout);
        response = await _closeRequest(request, timeout);
        body = await utf8.decodeStream(response).timeout(timeout);
      } catch (_) {
        request.abort();
        rethrow;
      }
      if (authorize &&
          response.statusCode == HttpStatus.unauthorized &&
          attempt < _authRetryDelays.length) {
        await Future<void>.delayed(_authRetryDelays[attempt]);
        continue;
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        final error = _tryJsonObject(body);
        final reasonCode = error?['reason_code']?.toString();
        final serverMessage = error?['error']?.toString();
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

  Future<HttpClientResponse> _closeRequest(
    HttpClientRequest request,
    Duration timeout,
  ) async {
    final error = TimeoutException(
      'Diagnostics request timed out after ${timeout.inMilliseconds} ms',
    );
    final timer = Timer(timeout, () => request.abort(error));
    try {
      return await request.close();
    } finally {
      timer.cancel();
    }
  }

  void close() {
    cancelSpeedTest();
    _healthFailures.clear();
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
