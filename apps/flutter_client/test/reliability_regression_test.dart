import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/nodes/nodes_page.dart';

PeerSnapshot _peer({
  String id = 'peer-a',
  int sent = 1000,
  int received = 2000,
}) => PeerSnapshot.fromJson({
  'node_id': id,
  'device_name': id,
  'virtual_ip': id == 'peer-a' ? '10.20.0.11' : '10.20.0.12',
  'online': true,
  'state': 'direct',
  'active_path': 'direct',
  'bytes_sent': sent,
  'bytes_received': received,
});

SpeedTestResult _result(String ip, {double rate = 42}) => SpeedTestResult(
  peerVirtualIp: ip,
  durationMs: 10000,
  downloadMbps: rate,
  uploadMbps: rate,
  downloadBytes: 1000,
  uploadBytes: 1000,
);

void main() {
  test(
    'three consecutive chart sessions have independent increasing time axes',
    () {
      final telemetry = SpeedTestTelemetry(maxSamples: 50);
      addTearDown(telemetry.dispose);
      for (var runId = 1; runId <= 3; runId++) {
        telemetry.reset(runId: runId, peer: _peer());
        for (var sample = 1; sample <= 5; sample++) {
          telemetry.recordPeer(
            _peer(
              sent: runId * 100000 + sample * 1000,
              received: runId * 200000 + sample * 2000,
            ),
            Duration(milliseconds: sample * 200),
            runId: runId,
          );
        }
        expect(telemetry.samples.map((point) => point.elapsedMs), [
          0,
          200,
          400,
          600,
          800,
          1000,
        ]);
        expect(telemetry.currentUploadMbps, closeTo(0.04, 0.000001));
        expect(telemetry.currentDownloadMbps, closeTo(0.08, 0.000001));
        expect(telemetry.uploadBytes, 4000);
        telemetry.recordResult(_result('10.20.0.11'), null, runId: runId);
      }
    },
  );

  test(
    'late samples and results cannot overwrite a new peer or finished session',
    () {
      final telemetry = SpeedTestTelemetry(maxSamples: 50);
      addTearDown(telemetry.dispose);
      telemetry.reset(runId: 1, peer: _peer());
      telemetry.recordPeer(
        _peer(),
        const Duration(milliseconds: 200),
        runId: 1,
      );
      telemetry.reset(runId: 2, peer: _peer(id: 'peer-b'));
      telemetry.recordPeer(
        _peer(sent: 999999),
        const Duration(seconds: 10),
        runId: 1,
      );
      telemetry.recordResult(_result('10.20.0.11'), null, runId: 1);
      expect(telemetry.samples.length, 1);
      expect(telemetry.elapsedMs, 0);
      expect(telemetry.result, isNull);
      telemetry.recordPeer(
        _peer(id: 'peer-b'),
        const Duration(milliseconds: 200),
        runId: 2,
      );
      telemetry.recordResult(_result('10.20.0.12'), null, runId: 2);
      final samples = telemetry.samples;
      telemetry.recordPeer(
        _peer(id: 'peer-b', sent: 900000),
        const Duration(seconds: 11),
        runId: 2,
      );
      expect(telemetry.samples, same(samples));
      expect(telemetry.result!.peerVirtualIp, '10.20.0.12');
    },
  );

  test(
    'counter resets cannot create spikes and backwards samples are ignored',
    () {
      final telemetry = SpeedTestTelemetry(maxSamples: 3);
      addTearDown(telemetry.dispose);
      telemetry.reset(runId: 1, peer: _peer());
      telemetry.recordPeer(
        _peer(sent: 100000),
        const Duration(milliseconds: 200),
        runId: 1,
      );
      telemetry.recordPeer(
        _peer(sent: 1, received: 1),
        const Duration(milliseconds: 400),
        runId: 1,
      );
      expect(telemetry.currentUploadMbps, 0);
      telemetry.recordPeer(
        _peer(sent: 999999),
        const Duration(milliseconds: 300),
        runId: 1,
      );
      expect(telemetry.elapsedMs, 400);
      telemetry.recordPeer(
        _peer(sent: 1001, received: 2001),
        const Duration(milliseconds: 600),
        runId: 1,
      );
      expect(telemetry.currentUploadMbps, closeTo(0.04, 0.000001));
      expect(telemetry.samples.length, 3);
    },
  );

  test('disposed chart rejects all late async writes', () {
    final telemetry = SpeedTestTelemetry(maxSamples: 50);
    telemetry.reset(runId: 1, peer: _peer());
    telemetry.dispose();
    expect(() {
      telemetry.recordPeer(_peer(), const Duration(seconds: 1), runId: 1);
      telemetry.tick(const Duration(seconds: 2), runId: 1);
      telemetry.recordResult(_result('10.20.0.11'), null, runId: 1);
      telemetry.reset(runId: 2, peer: _peer());
    }, returnsNormally);
  });

  test(
    'cancelled store request cannot end or overwrite its successor',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      final first = harness.store.runSpeedTest(_peer());
      final firstId = harness.store.speedTestRunId;
      harness.store.cancelSpeedTest();
      final second = harness.store.runSpeedTest(_peer(id: 'peer-b'));
      expect(harness.store.speedTestRunId, greaterThan(firstId));
      harness.api.tests[0].complete(_result('10.20.0.11', rate: 999));
      await first;
      expect(harness.store.speedTestRunning, isTrue);
      expect(harness.store.lastSpeedTestResult, isNull);
      harness.api.tests[1].complete(_result('10.20.0.12'));
      await second;
      expect(harness.store.speedTestRunning, isFalse);
      expect(harness.store.lastSpeedTestResult!.peerVirtualIp, '10.20.0.12');
      expect(harness.store.speedTestStartedAt, isNull);
    },
  );

  test('endpoint changes invalidate an in-flight speed test', () async {
    final harness = await _Harness.create();
    addTearDown(harness.dispose);
    final test = harness.store.runSpeedTest(_peer());
    await harness.settings.updateDiagnosticsUrl(
      'http://127.0.0.1:49152/status',
    );
    expect(harness.store.speedTestRunning, isFalse);
    harness.api.tests.single.complete(_result('10.20.0.11'));
    await test;
    expect(harness.store.lastSpeedTestResult, isNull);
    await harness.store.refresh();
  });

  test('disposing a store fences late test and snapshot completion', () async {
    final harness = await _Harness.create();
    final test = harness.store.runSpeedTest(_peer());
    harness.api.statusGate = Completer<DiagnosticsSnapshot>();
    final refresh = harness.store.refresh();
    await Future<void>.delayed(Duration.zero);
    harness.store.dispose();
    harness.api.tests.single.complete(_result('10.20.0.11'));
    harness.api.statusGate!.complete(harness.api.snapshot);
    await Future.wait([test, refresh]);
    harness.settings.dispose();
    await harness.directory.delete(recursive: true);
  });

  test(
    'startup catalog retries health failures until the service binds',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      await harness.settings.updateSettings(
        harness.settings.settings.copyWith(
          authToken: 'fixture-token',
          manualMode: false,
        ),
      );
      harness.api.healthResponses.addAll([false, false, true]);
      await harness.store.refreshUntilPeerCatalogSettled();
      expect(harness.api.healthCalls, greaterThanOrEqualTo(3));
      expect(harness.store.healthReachable, isTrue);
      expect(harness.store.snapshot, isNotNull);
      expect(harness.store.lastHealthError, isNull);
      expect(harness.store.startupCatalogSettling, isFalse);
    },
  );

  test(
    'automatic health failures become stale before becoming offline',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      await harness.store.refresh();
      harness.api.health = false;
      await harness.store.refresh(silent: true);
      expect(harness.store.snapshot, isNotNull);
      expect(harness.store.healthReachable, isFalse);
      expect(harness.store.snapshotStale, isTrue);
      await harness.store.refresh(silent: true);
      await harness.store.refresh(silent: true);
      expect(harness.store.snapshot, isNull);
      expect(harness.store.lastHealthError, isNotNull);
    },
  );

  test(
    'health rejects non-health services and retains HTTP failure details',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      var status = 200;
      var body = '<html>wrong service</html>';
      server.listen((request) async {
        request.response.statusCode = status;
        request.response.write(body);
        await request.response.close();
      });
      final api = DiagnosticsApi(authTokenReader: () async => null);
      addTearDown(api.close);
      final url = 'http://127.0.0.1:${server.port}';
      expect(await api.fetchHealth(url), isFalse);
      expect(api.healthFailureFor(url)!.reasonCode, 'health_invalid_response');
      status = 503;
      body = 'busy';
      expect(await api.fetchHealth(url), isFalse);
      expect(api.healthFailureFor(url)!.statusCode, 503);
      status = 200;
      body = 'ok\n';
      expect(await api.fetchHealth(url), isTrue);
      expect(api.healthFailureFor(url), isNull);
    },
  );

  test(
    'API cancellation releases a pending request without closing health client',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final entered = Completer<void>();
      final release = Completer<void>();
      server.listen((request) async {
        if (request.uri.path == '/speedtest') {
          entered.complete();
          await release.future;
          request.response.write('{}');
        } else {
          request.response.write('ok\n');
        }
        try {
          await request.response.close();
        } catch (_) {}
      });
      final api = DiagnosticsApi(authTokenReader: () async => 'fixture-secret');
      addTearDown(() async {
        if (!release.isCompleted) release.complete();
        api.close();
        await server.close(force: true);
      });
      final url = 'http://127.0.0.1:${server.port}';
      final running = api.runSpeedTest(url, peerVirtualIp: '10.20.0.11');
      final expectation = expectLater(
        running,
        throwsA(isA<DiagnosticsApiException>()),
      );
      await entered.future;
      api.cancelSpeedTest();
      await expectation.timeout(const Duration(seconds: 1));
      expect(await api.fetchHealth(url), isTrue);
      release.complete();
    },
  );
}

class _Api extends DiagnosticsApi {
  _Api(this.snapshot);
  final DiagnosticsSnapshot snapshot;
  var health = true;
  var healthCalls = 0;
  final healthResponses = <bool>[];
  final tests = <Completer<SpeedTestResult>>[];
  Completer<DiagnosticsSnapshot>? statusGate;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async {
    healthCalls += 1;
    return healthResponses.isEmpty ? health : healthResponses.removeAt(0);
  }

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) =>
      statusGate?.future ?? Future.value(snapshot);

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async =>
      const RoutesResponse(
        contractVersion: 1,
        interfaceName: 'p2wlan',
        mtu: 1500,
        healthy: true,
        conflictCount: 0,
        entries: [],
      );

  @override
  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) {
    final request = Completer<SpeedTestResult>();
    tests.add(request);
    return request.future;
  }
}

class _Harness {
  _Harness(this.directory, this.settings, this.api, this.store);
  final Directory directory;
  final SettingsStore settings;
  final _Api api;
  final StatusStore store;

  static Future<_Harness> create() async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_reliability_',
    );
    final settings = SettingsStore(
      settingsFile: File('${directory.path}/settings.json'),
      tokenRepository: InMemorySecureTokenRepository(),
    );
    await settings.load();
    final raw = jsonDecode(
      await File('test/fixtures/status_connected.json').readAsString(),
    ) as Map<String, dynamic>;
    final api = _Api(DiagnosticsSnapshot.fromJson(raw));
    final store = StatusStore(
      settingsStore: settings,
      diagnosticsApi: api,
      enableEventPolling: false,
      startupCatalogRefreshInterval: const Duration(milliseconds: 1),
      startupCatalogRefreshTimeout: const Duration(milliseconds: 100),
    );
    return _Harness(directory, settings, api, store);
  }

  Future<void> dispose() async {
    store.dispose();
    settings.dispose();
    await directory.delete(recursive: true);
  }
}
