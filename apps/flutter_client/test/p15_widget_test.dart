import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';
import 'package:p2wlan_flutter_client/features/diagnostics/diagnostics_page.dart';
import 'package:p2wlan_flutter_client/features/settings/settings_page.dart';

void main() {
  testWidgets('Dashboard renders offline/error state without crashing', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Offline'), findsWidgets);
    expect(find.text('GET /health'), findsOneWidget);
    expect(find.text('GET /status'), findsOneWidget);
    expect(find.text('skipped'), findsOneWidget);
    expect(find.textContaining('GET /health is offline'), findsWidgets);
    expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
    expect(find.byKey(const Key('auto-refresh-switch')), findsOneWidget);
  });

  testWidgets('Dashboard separates status endpoint errors from health', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(
          health: true,
          statusError: const DiagnosticsApiException('status fixture failed'),
        ),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Degraded'), findsWidgets);
    expect(find.text('reachable'), findsOneWidget);
    expect(find.text('error'), findsOneWidget);
    expect(find.textContaining('GET /status failed'), findsWidgets);
  });

  testWidgets('Settings validates diagnostics URL before saving', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
    ))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      _TestApp(
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    await tester.enterText(find.byType(TextField), 'ftp://127.0.0.1:39277');
    await tester.tap(find.text('Save'));
    await tester.pump();

    expect(find.text('Diagnostics URL must use http or https'), findsOneWidget);
    expect(find.text('Diagnostics URL was not saved'), findsOneWidget);
  });

  testWidgets('Diagnostics renders summary, raw JSON, and copy action', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    expect(find.text('Summary'), findsOneWidget);
    expect(find.text('Raw /status JSON'), findsOneWidget);
    expect(find.text('Healthy'), findsWidgets);
    expect(find.text('Show JSON'), findsOneWidget);
    expect(
      find.textContaining('Full JSON is not rendered by default'),
      findsOneWidget,
    );

    await tester.tap(find.text('Show JSON'));
    await tester.pump();

    expect(
      find.textContaining('"node_id": "node-local-abcdef1234567890"'),
      findsOneWidget,
    );

    expect(find.text('Copy'), findsOneWidget);
    await tester.tap(find.text('Copy'));
    await tester.pump();

    expect(tester.takeException(), isNull);
  });
}

Future<DiagnosticsSnapshot> _loadFixtureSnapshot() async {
  final raw = await File('test/fixtures/status_connected.json').readAsString();
  return DiagnosticsSnapshot.fromJson(jsonDecode(raw) as Map<String, dynamic>);
}

Future<_Stores> _makeStores({required DiagnosticsApi api}) async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_flutter_test_');
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
  );
  await settingsStore.load();
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    daemonController: _FakeDaemonController(api),
    autoRefreshInterval: const Duration(minutes: 5),
  );
  return _Stores(tempDir, settingsStore, statusStore);
}

class _Stores {
  _Stores(this.tempDir, this.settingsStore, this.statusStore);

  final Directory tempDir;
  final SettingsStore settingsStore;
  final StatusStore statusStore;

  void dispose() {
    statusStore.dispose();
    settingsStore.dispose();
    tempDir.deleteSync(recursive: true);
  }
}

class _FakeDiagnosticsApi implements DiagnosticsApi {
  _FakeDiagnosticsApi({required this.health, this.snapshot, this.statusError});

  final bool health;
  final DiagnosticsSnapshot? snapshot;
  final Object? statusError;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => health;

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => true;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    final error = statusError;
    if (error != null) throw error;
    final value = snapshot;
    if (value == null) {
      throw const DiagnosticsApiException('missing fixture snapshot');
    }
    return value;
  }

  @override
  void close() {}
}

class _FakeDaemonController extends DaemonController {
  _FakeDaemonController(DiagnosticsApi api) : super(diagnosticsApi: api);

  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    return const DaemonCommandResult(ok: true, message: 'fake start');
  }

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    return const DaemonCommandResult(ok: true, message: 'fake stop');
  }
}

class _TestApp extends StatelessWidget {
  const _TestApp({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: ScaffoldMessenger(child: Scaffold(body: child)),
    );
  }
}
