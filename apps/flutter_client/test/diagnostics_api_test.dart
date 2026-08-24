import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';

void main() {
  group('normalizeDiagnosticsUrl', () {
    test('keeps the diagnostics default status URL', () {
      expect(
        normalizeDiagnosticsUrl(defaultDiagnosticsUrl),
        defaultDiagnosticsUrl,
      );
    });

    test('trims whitespace and adds /status when no path is provided', () {
      expect(
        normalizeDiagnosticsUrl('  http://127.0.0.1:39277  '),
        'http://127.0.0.1:39277/status',
      );
    });

    test('normalizes root path to /status', () {
      expect(
        normalizeDiagnosticsUrl('http://localhost:39277/'),
        'http://localhost:39277/status',
      );
    });

    test('preserves an explicit status path and query', () {
      expect(
        normalizeDiagnosticsUrl('http://localhost:39277/status?probe=1'),
        'http://localhost:39277/status?probe=1',
      );
    });

    test('allows https loopback-compatible URLs for future IPC hardening', () {
      expect(
        normalizeDiagnosticsUrl('https://localhost:39277/status'),
        'https://localhost:39277/status',
      );
    });

    test('rejects diagnostics endpoints that would expose local control', () {
      expect(
        () => normalizeDiagnosticsUrl('http://0.0.0.0:39277/status'),
        throwsFormatException,
      );
      expect(
        () => normalizeDiagnosticsUrl('http://192.0.2.12:39277/status'),
        throwsFormatException,
      );
    });

    test('rejects missing URL, unsupported scheme, and missing host', () {
      expect(() => normalizeDiagnosticsUrl(''), throwsFormatException);
      expect(
        () => normalizeDiagnosticsUrl('ws://127.0.0.1:39277/status'),
        throwsFormatException,
      );
      expect(
        () => normalizeDiagnosticsUrl('http:///status'),
        throwsFormatException,
      );
    });
  });

  test(
    'authorizes sensitive GETs and retries a startup 401 with a fresh token',
    () async {
      final fixture = await File(
        '../../contracts/fixtures/status.json',
      ).readAsString();
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      var statusRequests = 0;
      var tokenReady = false;
      final headers = <String?>[];
      server.listen((request) async {
        if (request.uri.path == '/health') {
          expect(
            request.headers.value(HttpHeaders.authorizationHeader),
            isNull,
          );
          request.response
            ..statusCode = HttpStatus.ok
            ..headers.contentType = ContentType.text
            ..write('ok\n');
          await request.response.close();
          return;
        }
        if (request.uri.path == '/status') {
          statusRequests++;
          headers.add(request.headers.value(HttpHeaders.authorizationHeader));
          if (statusRequests == 1) {
            tokenReady = true;
            request.response.statusCode = HttpStatus.unauthorized;
            await request.response.close();
            return;
          }
          request.response
            ..statusCode = HttpStatus.ok
            ..headers.contentType = ContentType.json
            ..write(fixture);
          await request.response.close();
        }
      });

      final api = DiagnosticsApi(
        authTokenReader: () async => tokenReady ? 'diag-test-token' : null,
      );
      addTearDown(api.close);
      final url = 'http://127.0.0.1:${server.port}/status';

      expect(await api.fetchHealth(url), isTrue);
      final status = await api.fetchStatus(url);
      expect(status.nodeId, 'node-a');
      expect(statusRequests, 2, reason: 'one daemon-session retry is allowed');
      expect(headers, [null, 'Bearer diag-test-token']);
    },
  );

  test('loopback diagnostics bypass an inherited HTTP proxy', () async {
    final diagnostics = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => diagnostics.close(force: true));
    diagnostics.listen((request) async {
      expect(request.uri.path, '/health');
      request.response
        ..statusCode = HttpStatus.ok
        ..headers.contentType = ContentType.text
        ..write('ok\n');
      await request.response.close();
    });

    var proxyRequests = 0;
    final proxy = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => proxy.close(force: true));
    proxy.listen((request) async {
      proxyRequests++;
      request.response.statusCode = HttpStatus.badGateway;
      await request.response.close();
    });

    final client = HttpClient()
      ..findProxy = (_) => 'PROXY 127.0.0.1:${proxy.port}';
    final api = DiagnosticsApi(
      client: client,
      authTokenReader: () async => null,
    );
    addTearDown(api.close);

    expect(
      await api.fetchHealth('http://127.0.0.1:${diagnostics.port}/status'),
      isTrue,
    );
    expect(proxyRequests, 0);
  });

  test('a timed-out diagnostics request aborts its socket', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    final accepted = Completer<Socket>();
    server.listen((socket) {
      if (!accepted.isCompleted) accepted.complete(socket);
    });

    final api = DiagnosticsApi(authTokenReader: () async => null);
    addTearDown(api.close);
    final health = api.fetchHealth('http://127.0.0.1:${server.port}/status');
    final socket = await accepted.future.timeout(const Duration(seconds: 1));
    addTearDown(socket.destroy);
    final disconnected = Completer<void>();
    socket.listen(
      (_) {},
      onError: (_) {
        if (!disconnected.isCompleted) disconnected.complete();
      },
      onDone: () {
        if (!disconnected.isCompleted) disconnected.complete();
      },
    );

    expect(await health, isFalse);
    await disconnected.future.timeout(const Duration(seconds: 1));
  });

  test('retries a structured diagnostics snapshot timeout', () async {
    final fixture = await File(
      '../../contracts/fixtures/status.json',
    ).readAsString();
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    var statusRequests = 0;
    server.listen((request) async {
      if (request.uri.path != '/status') return;
      statusRequests++;
      if (statusRequests == 1) {
        request.response
          ..statusCode = HttpStatus.serviceUnavailable
          ..headers.contentType = ContentType.json
          ..write(
            '{"error":"diagnostics snapshot timed out",'
            '"reason_code":"status_snapshot_timeout"}',
          );
      } else {
        request.response
          ..statusCode = HttpStatus.ok
          ..headers.contentType = ContentType.json
          ..write(fixture);
      }
      await request.response.close();
    });

    final api = DiagnosticsApi(authTokenReader: () async => 'diag-test-token');
    addTearDown(api.close);

    final status = await api.fetchStatus(
      'http://127.0.0.1:${server.port}/status',
    );
    expect(status.nodeId, 'node-a');
    expect(statusRequests, 2);
  });
}
