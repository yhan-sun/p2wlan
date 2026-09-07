import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';

void main() {
  test(
    'ready local start without credentials does not wait for a managed roster',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      final result = await harness.store.startDaemon().timeout(
        const Duration(seconds: 1),
      );
      expect(result.ok, isTrue);
      expect(harness.api.healthCalls, 1);
      expect(harness.store.daemonStarting, isFalse);
      expect(harness.store.snapshot, isNotNull);
    },
  );

  test(
    'unexpected daemon exceptions do not enter user-facing error fields',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      harness.controller.throwOnStart = true;
      final result = await harness.store.startDaemon();
      expect(result.ok, isFalse);
      expect(result.message, 'daemon_operation_failed');
      expect(harness.store.lastError, 'daemon_operation_failed');
      expect(harness.store.lastDaemonMessage, isNot(contains('SECRET')));
    },
  );

  testWidgets('an explicit daemon start shows progress then a ready snapshot', (
    tester,
  ) async {
    final harness = (await tester.runAsync(_Harness.create))!;
    addTearDown(harness.dispose);
    harness.api.health = false;
    harness.controller.startGate = Completer<DaemonCommandResult>();
    await tester.pumpWidget(harness.app('en'));
    final pending = harness.store.startDaemon();
    await tester.pump();
    expect(find.text('Connecting to P2WLAN'), findsOneWidget);
    expect(find.text('Cannot reach P2WLAN'), findsNothing);
    expect(find.textContaining('GET /health'), findsNothing);
    harness.api.health = true;
    harness.controller.startGate!.complete(
      const DaemonCommandResult(ok: true, message: 'ready'),
    );
    await pending;
    await tester.pump();
    expect(harness.store.snapshot, isNotNull);
    expect(find.text('Connecting to P2WLAN'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  for (final locale in ['en', 'zh-Hans']) {
    testWidgets('startup failure is safe and localized in $locale', (
      tester,
    ) async {
      final harness = (await tester.runAsync(_Harness.create))!;
      addTearDown(harness.dispose);
      harness.api.health = false;
      harness.controller.result = const DaemonCommandResult(
        ok: false,
        message: 'SocketException SECRET bearer_token=secret',
        failureCode: DaemonStartupFailureCode.uacCancelled,
      );
      await tester.pumpWidget(harness.app(locale));
      await harness.store.startDaemon();
      await tester.pump();
      expect(
        find.text(AppStrings.fromCode(locale).windowsUacCancelled),
        findsOneWidget,
      );
      expect(find.textContaining('SECRET'), findsNothing);
      expect(find.textContaining('SocketException'), findsNothing);
      expect(harness.store.daemonStarting, isFalse);
      expect(tester.takeException(), isNull);
    });
  }
}

class _Api extends DiagnosticsApi {
  _Api(this.snapshot);
  final DiagnosticsSnapshot snapshot;
  var health = true;
  var healthCalls = 0;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async {
    healthCalls += 1;
    return health;
  }

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async =>
      snapshot;

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
}

class _Controller extends DaemonController {
  _Controller(DiagnosticsApi api) : super(diagnosticsApi: api);
  var throwOnStart = false;
  var result = const DaemonCommandResult(ok: true, message: 'ready');
  Completer<DaemonCommandResult>? startGate;

  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    if (throwOnStart) throw StateError('SocketException SECRET');
    return startGate?.future ?? Future.value(result);
  }
}

class _Harness {
  _Harness(
    this.directory,
    this.settings,
    this.api,
    this.controller,
    this.store,
  );
  final Directory directory;
  final SettingsStore settings;
  final _Api api;
  final _Controller controller;
  final StatusStore store;

  static Future<_Harness> create() async {
    final directory = await Directory.systemTemp.createTemp('p2wlan_startup_');
    final settings = SettingsStore(
      settingsFile: File('${directory.path}/settings.json'),
      tokenRepository: InMemorySecureTokenRepository(),
    );
    await settings.load();
    final raw = jsonDecode(
      await File('test/fixtures/status_connected.json').readAsString(),
    ) as Map<String, dynamic>;
    final api = _Api(DiagnosticsSnapshot.fromJson(raw));
    final controller = _Controller(api);
    final store = StatusStore(
      settingsStore: settings,
      diagnosticsApi: api,
      daemonController: controller,
      enableEventPolling: false,
    );
    return _Harness(directory, settings, api, controller, store);
  }

  Widget app(String locale) => MaterialApp(
    home: AppStringsScope(
      strings: AppStrings.fromCode(locale),
      child: Scaffold(
        body: DashboardPage(settingsStore: settings, statusStore: store),
      ),
    ),
  );

  Future<void> dispose() async {
    store.dispose();
    settings.dispose();
    await directory.delete(recursive: true);
  }
}
