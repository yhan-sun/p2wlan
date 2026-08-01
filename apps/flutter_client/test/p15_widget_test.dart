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
import 'package:p2wlan_flutter_client/features/nodes/nodes_page.dart';
import 'package:p2wlan_flutter_client/features/settings/settings_page.dart';
import 'package:p2wlan_flutter_client/features/tunnels/tunnels_page.dart';

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

    expect(find.textContaining('Start P2WLAN to see virtual IP'), findsWidgets);
    expect(find.text('Needs attention'), findsNothing);
    expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
    expect(find.byKey(const Key('auto-refresh-toggle')), findsOneWidget);
  });

  testWidgets('Dashboard shows stop only when daemon is reachable', (
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
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
  });

  testWidgets('StatusStore settles peer catalog after daemon start', (
    tester,
  ) async {
    final fullSnapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final partialSnapshot = _snapshotWithPeerCount(fullSnapshot, 1);
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshots: [partialSnapshot, fullSnapshot, fullSnapshot],
    );
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: api,
        startupCatalogRefreshInterval: Duration.zero,
        startupCatalogRefreshTimeout: const Duration(seconds: 1),
      ),
    ))!;
    addTearDown(stores.dispose);

    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(
          authToken: 'token',
          manualMode: false,
        ),
      ),
    );
    await tester.runAsync(stores.statusStore.startDaemon);

    expect(stores.statusStore.snapshot?.peers, hasLength(2));
    expect(api.statusFetchCount, greaterThanOrEqualTo(3));
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

    expect(find.textContaining('GET /status failed'), findsWidgets);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
  });

  testWidgets('Dashboard keeps actions usable on narrow screens', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
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

    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
    expect(find.byKey(const Key('auto-refresh-toggle')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Settings validates diagnostics URL before saving', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

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

    final diagnosticsField = find.byWidgetPredicate(
      (widget) =>
          widget is TextField &&
          widget.decoration?.labelText == 'Diagnostics URL',
    );
    await tester.enterText(diagnosticsField, 'ftp://127.0.0.1:39277');
    final saveButton = find.byKey(const Key('settings-save-button'));
    await tester.tap(saveButton);
    await tester.pump();

    expect(find.text('Diagnostics URL must use http or https'), findsOneWidget);
    expect(find.text('Diagnostics URL was not saved'), findsOneWidget);
  });

  testWidgets('Settings keeps network fields usable on narrow screens', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

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

    expect(find.text('Network and Tunnel'), findsOneWidget);
    expect(find.text('Interface name'), findsOneWidget);
    expect(find.text('UDP advertise'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes renders local device and readable peer sections', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(
          authToken: 'token',
          deviceName: 'studio-mac',
          manualMode: false,
        ),
      ),
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('This device'), findsOneWidget);
    expect(find.text('studio-mac'), findsOneWidget);
    expect(find.text('Device summary'), findsOneWidget);
    expect(find.text('Other devices'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('Peer 数'), findsNothing);
  });

  testWidgets('Nodes keeps peer list readable on narrow screens', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(deviceName: 'studio-mac'),
      ),
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Other devices'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('10.20.0.11'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes shows peer RTT for online relay peers', (tester) async {
    final snapshot = (await tester.runAsync(() async {
      final raw =
          jsonDecode(
                await File(
                  'test/fixtures/status_connected.json',
                ).readAsString(),
              )
              as Map<String, dynamic>;
      final relaySelection = raw['relay_selection'] as Map<String, dynamic>;
      relaySelection['selected_rtt_ewma_ms'] = 25;
      relaySelection['selected_last_pong_rtt_ms'] = 19;
      final peers = raw['peers'] as List<dynamic>;
      final relayPeer = peers.cast<Map<String, dynamic>>().firstWhere(
        (peer) => peer['node_id'] == 'peer-relay-002',
      );
      relayPeer['online'] = true;
      relayPeer['state'] = 'relay';
      relayPeer['active_path'] = 'relay';
      (relayPeer['direct'] as Map<String, dynamic>)['latency_ms'] = null;
      (relayPeer['direct'] as Map<String, dynamic>)['rtt_ewma_ms'] = null;
      (relayPeer['relay'] as Map<String, dynamic>)['latency_ms'] = 58;
      (relayPeer['relay'] as Map<String, dynamic>)['rtt_ewma_ms'] = 52;
      return DiagnosticsSnapshot.fromJson(raw);
    }))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('52 ms'), findsOneWidget);
    expect(find.text('25 ms'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes keeps errored offline peers in the offline group', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(() async {
      final raw =
          jsonDecode(
                await File(
                  'test/fixtures/status_connected.json',
                ).readAsString(),
              )
              as Map<String, dynamic>;
      final peers = raw['peers'] as List<dynamic>;
      for (final peer in peers.cast<Map<String, dynamic>>()) {
        final direct = peer['direct'] as Map<String, dynamic>;
        direct['last_error'] = null;
      }
      peers.addAll([
        {
          'node_id': 'offline-errored-001',
          'device_name': 'offline-with-error',
          'virtual_ip': '10.20.0.20',
          'online': false,
          'last_seen': 1784710187,
          'state': 'closed',
          'active_path': null,
          'direct_type': 'unknown',
          'is_relay': false,
          'direct': {
            'last_error':
                'no direct probe ACK after 320 background UDP retry probes',
          },
          'relay': <String, dynamic>{},
        },
        {
          'node_id': 'offline-plain-002',
          'device_name': 'offline-plain',
          'virtual_ip': '10.20.0.21',
          'online': false,
          'last_seen': 1784710100,
          'state': 'closed',
          'active_path': null,
          'direct_type': 'unknown',
          'is_relay': false,
          'direct': <String, dynamic>{},
          'relay': <String, dynamic>{},
        },
      ]);
      return DiagnosticsSnapshot.fromJson(raw);
    }))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    final offlineGroupHeader = find.text('Offline devices').last;
    final erroredOffline = find.text('offline-with-error');
    final plainOffline = find.text('offline-plain');
    expect(offlineGroupHeader, findsOneWidget);
    expect(erroredOffline, findsOneWidget);
    expect(plainOffline, findsOneWidget);
    expect(
      tester.getTopLeft(erroredOffline).dy,
      greaterThan(tester.getTopLeft(offlineGroupHeader).dy),
    );
    expect(
      tester.getTopLeft(plainOffline).dy,
      greaterThan(tester.getTopLeft(offlineGroupHeader).dy),
    );
    expect(
      find.text('no direct probe ACK after 320 background UDP retry probes'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes remove action opens a visible confirmation dialog', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    await tester.tap(find.byTooltip('Device actions').first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Remove device').last);
    await tester.pumpAndSettle();

    expect(find.byType(AlertDialog), findsOneWidget);
    expect(
      find.textContaining('This removes the device from the control plane'),
      findsOneWidget,
    );
    expect(find.text('direct-laptop'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes details action opens a visible bounded dialog', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    await tester.tap(find.byTooltip('Device actions').first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('View details').last);
    await tester.pumpAndSettle();

    expect(find.byType(Dialog), findsOneWidget);
    expect(find.text('Connection type'), findsOneWidget);
    expect(find.text('Node ID'), findsWidgets);
    expect(find.byType(SelectableText), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Tunnels keeps detail rows readable on narrow screens', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: TunnelsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Tunnel summary'), findsOneWidget);
    expect(find.text('Virtual Adapter'), findsOneWidget);
    expect(find.text('192.0.2.10:60207'), findsOneWidget);
    expect(tester.takeException(), isNull);
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

    tester
        .widget<OutlinedButton>(
          find.widgetWithText(OutlinedButton, 'Show JSON'),
        )
        .onPressed!();
    await tester.pump();

    expect(
      find.textContaining('"node_id": "node-local-abcdef1234567890"'),
      findsOneWidget,
    );

    expect(find.text('Copy'), findsWidgets);
    tester
        .widget<OutlinedButton>(
          find.widgetWithText(OutlinedButton, 'Copy').first,
        )
        .onPressed!();
    await tester.pump();

    expect(tester.takeException(), isNull);
  });
}

Future<DiagnosticsSnapshot> _loadFixtureSnapshot() async {
  final raw = await File('test/fixtures/status_connected.json').readAsString();
  return DiagnosticsSnapshot.fromJson(jsonDecode(raw) as Map<String, dynamic>);
}

DiagnosticsSnapshot _snapshotWithPeerCount(
  DiagnosticsSnapshot snapshot,
  int peerCount,
) {
  final raw = jsonDecode(jsonEncode(snapshot.raw)) as Map<String, dynamic>;
  raw['peers'] = (raw['peers'] as List<dynamic>).take(peerCount).toList();
  (raw['stats'] as Map<String, dynamic>)['total_peers'] = peerCount;
  return DiagnosticsSnapshot.fromJson(raw);
}

Future<_Stores> _makeStores({
  required DiagnosticsApi api,
  Duration startupCatalogRefreshInterval =
      StatusStore.defaultStartupCatalogRefreshInterval,
  Duration startupCatalogRefreshTimeout =
      StatusStore.defaultStartupCatalogRefreshTimeout,
}) async {
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
    startupCatalogRefreshInterval: startupCatalogRefreshInterval,
    startupCatalogRefreshTimeout: startupCatalogRefreshTimeout,
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
  _FakeDiagnosticsApi({
    required this.health,
    this.snapshot,
    this.snapshots,
    this.statusError,
  });

  final bool health;
  final DiagnosticsSnapshot? snapshot;
  final List<DiagnosticsSnapshot>? snapshots;
  final Object? statusError;
  var statusFetchCount = 0;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => health;

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => true;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    statusFetchCount += 1;
    final error = statusError;
    if (error != null) throw error;
    final sequence = snapshots;
    if (sequence != null && sequence.isNotEmpty) {
      final index = statusFetchCount - 1;
      if (index < sequence.length) return sequence[index];
      return sequence.last;
    }
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
