import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/desktop_tray_controller.dart';
import 'package:p2wlan_flutter_client/app/desktop_window_status_controller.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';

void main() {
  test('desktop tray shows start as the offline primary control', () async {
    final stores = await _makeStores(api: DiagnosticsApi());
    addTearDown(stores.dispose);

    final labels = _labels(
      DesktopTrayController(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
      ),
    );

    expect(labels, contains('打开控制台'));
    expect(labels, contains('启动 P2WLAN'));
    expect(labels, isNot(contains('停止 P2WLAN')));
    expect(labels, contains('打开日志'));
    expect(labels, contains('退出 P2WLAN'));
  });

  test('desktop tray shows stop as the reachable primary control', () async {
    final snapshot = await _loadFixtureSnapshot();
    final stores = await _makeStores(
      api: _FakeDiagnosticsApi(snapshot: snapshot),
    );
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    final labels = _labels(
      DesktopTrayController(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
      ),
    );

    expect(labels, contains('停止 P2WLAN'));
    expect(labels, isNot(contains('启动 P2WLAN')));
    expect(labels.any((label) => label.contains('本端平均 RTT: 34 ms')), isTrue);
    expect(labels.any((label) => label.contains('传输速度: —')), isTrue);
  });

  test('desktop tray online-device submenu excludes offline peers', () async {
    final raw =
        jsonDecode(
              await File('test/fixtures/status_connected.json').readAsString(),
            )
            as Map<String, dynamic>;
    final peers = raw['peers'] as List<dynamic>;
    final offline =
        Map<String, dynamic>.from(peers.first as Map<String, dynamic>)
          ..['node_id'] = 'offline-peer'
          ..['device_name'] = 'offline-device'
          ..['virtual_ip'] = '10.20.0.99'
          ..['online'] = false;
    peers.add(offline);
    final stores = await _makeStores(
      api: _FakeDiagnosticsApi(snapshot: DiagnosticsSnapshot.fromJson(raw)),
    );
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    final menu = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    ).buildMenuForTesting();
    final devices = menu.items!.firstWhere((item) => item.label == '设备');
    final labels = devices.submenu!.items!
        .map((item) => item.label)
        .whereType<String>()
        .toList();

    expect(labels.any((label) => label.contains('direct-laptop')), isTrue);
    expect(labels.any((label) => label.contains('relay-nas')), isTrue);
    expect(labels.any((label) => label.contains('offline-device')), isFalse);
  });

  test('desktop tray device submenu marks direct and relay paths', () async {
    final snapshot = await _loadFixtureSnapshot();
    final stores = await _makeStores(
      api: _FakeDiagnosticsApi(snapshot: snapshot),
    );
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    final menu = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    ).buildMenuForTesting();
    final devices = menu.items!.firstWhere((item) => item.label == '设备');
    final labels = devices.submenu!.items!
        .map((item) => item.label)
        .whereType<String>()
        .toList();

    expect(labels.any((label) => label.contains('🟢 直连')), isTrue);
    expect(labels.any((label) => label.contains('🟠 中继')), isTrue);
  });

  test(
    'desktop tray icon exposes offline state without opening the menu',
    () async {
      final stores = await _makeStores(api: DiagnosticsApi());
      addTearDown(stores.dispose);

      final controller = DesktopTrayController(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
      );

      expect(
        controller.trayIconAssetForTesting(),
        _expectedTrayIconAsset('assets/tray_icon_macos_off.png'),
      );
    },
  );

  test('desktop tray uses template rendering on macOS', () async {
    final stores = await _makeStores(api: DiagnosticsApi());
    addTearDown(stores.dispose);

    final controller = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );

    expect(controller.trayIconUsesTemplateForTesting(), Platform.isMacOS);
  });

  test('desktop tray title keeps the app visible when offline', () async {
    final stores = await _makeStores(api: DiagnosticsApi());
    addTearDown(stores.dispose);

    final controller = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );

    expect(controller.trayTitleForTesting(), 'P2WLAN');
    expect(controller.dockBadgeForTesting(), isEmpty);
  });

  test('macOS tray item keeps only the icon in the menu bar', () async {
    final stores = await _makeStores(api: DiagnosticsApi());
    addTearDown(stores.dispose);

    final controller = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );

    expect(
      controller.trayMenuBarTitleForTesting(),
      Platform.isMacOS ? isEmpty : 'P2WLAN',
    );
  });

  test('desktop tray title includes verified latency', () async {
    final snapshot = await _loadFixtureSnapshot();
    final stores = await _makeStores(
      api: _FakeDiagnosticsApi(snapshot: snapshot),
    );
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    final controller = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );

    expect(controller.trayTitleForTesting(), contains('34 ms'));
    expect(controller.trayTitleForTesting(), contains('—'));
    expect(controller.dockBadgeForTesting(), '34ms/—');
  });

  test('desktop taskbar status includes verified latency', () async {
    final snapshot = await _loadFixtureSnapshot();
    final stores = await _makeStores(
      api: _FakeDiagnosticsApi(snapshot: snapshot),
    );
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    final controller = DesktopWindowStatusController(
      statusStore: stores.statusStore,
    );

    expect(controller.taskbarTitleForTesting(), contains('34 ms'));
    expect(controller.dockBadgeForTesting(), '34ms/—');
  });

  test('macOS OS chrome does not expose live connection metrics', () async {
    final snapshot = await _loadFixtureSnapshot();
    final stores = await _makeStores(
      api: _FakeDiagnosticsApi(snapshot: snapshot),
    );
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    final tray = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );
    final window = DesktopWindowStatusController(
      statusStore: stores.statusStore,
    );

    if (Platform.isMacOS) {
      expect(tray.desktopVisibleTitleForTesting(), 'P2WLAN');
      expect(tray.desktopVisibleBadgeForTesting(), isEmpty);
      expect(window.desktopVisibleTitleForTesting(), 'P2WLAN');
      expect(window.desktopVisibleBadgeForTesting(), isEmpty);
    }
  });

  test(
    'desktop tray icon exposes healthy state without opening the menu',
    () async {
      final snapshot = await _loadFixtureSnapshot();
      final stores = await _makeStores(
        api: _FakeDiagnosticsApi(snapshot: snapshot),
      );
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();

      final controller = DesktopTrayController(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
      );

      expect(
        controller.trayIconAssetForTesting(),
        _expectedTrayIconAsset('assets/tray_icon_macos_on.png'),
      );
    },
  );

  test('desktop tray icon flags reachable degraded state', () async {
    final snapshot = await _loadFixtureSnapshot(healthStatus: 'degraded');
    final stores = await _makeStores(
      api: _FakeDiagnosticsApi(snapshot: snapshot),
    );
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    final controller = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );

    expect(
      controller.trayIconAssetForTesting(),
      _expectedTrayIconAsset('assets/tray_icon_macos_attention.png'),
    );
  });

  test('desktop tray close action follows close behavior setting', () async {
    final stores = await _makeStores(api: DiagnosticsApi());
    addTearDown(stores.dispose);

    final controller = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );

    expect(controller.closeActionForTesting(), 'hide');

    await stores.settingsStore.updateSettings(
      stores.settingsStore.settings.copyWith(
        manualMode: true,
        closeBehavior: 'stop-and-quit',
      ),
    );

    expect(controller.closeActionForTesting(), 'quit');
  });

  test('desktop tray quit waits for an in-flight stop command', () async {
    final snapshot = await _loadFixtureSnapshot();
    final api = _FakeDiagnosticsApi(snapshot: snapshot);
    final stopCompleter = Completer<DaemonCommandResult>();
    final daemonController = _DelayedStopDaemonController(
      diagnosticsApi: api,
      stopCompleter: stopCompleter,
    );
    final stores = await _makeStores(
      api: api,
      daemonController: daemonController,
    );
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    final controller = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );

    final stopFuture = controller.stopDaemonForTesting();
    expect(stores.statusStore.daemonBusy, isTrue);
    expect(daemonController.stopCalls, 1);

    final quitStopFuture = controller.stopDaemonForQuitForTesting();
    expect(quitStopFuture, same(stopFuture));
    expect(daemonController.stopCalls, 1);

    stopCompleter.complete(
      const DaemonCommandResult(ok: true, message: 'fake stop'),
    );

    final result = await quitStopFuture;
    expect(result.ok, isTrue);
    expect(daemonController.stopCalls, 1);
  });

  test('desktop tray quit skips stop when daemon is already offline', () async {
    final api = _FakeDiagnosticsApi(snapshot: null);
    final daemonController = _CountingStopDaemonController(diagnosticsApi: api);
    final stores = await _makeStores(
      api: api,
      daemonController: daemonController,
    );
    addTearDown(stores.dispose);

    final controller = DesktopTrayController(
      settingsStore: stores.settingsStore,
      statusStore: stores.statusStore,
    );

    final result = await controller.stopDaemonForQuitForTesting();

    expect(result.ok, isTrue);
    expect(daemonController.stopCalls, 0);
  });

  test(
    'desktop tray quit proceeds when redundant stop finds daemon offline',
    () async {
      final snapshot = await _loadFixtureSnapshot();
      final api = _FakeDiagnosticsApi(snapshot: snapshot);
      final daemonController = _OfflineAfterFailedStopDaemonController(
        diagnosticsApi: api,
        api: api,
      );
      final stores = await _makeStores(
        api: api,
        daemonController: daemonController,
      );
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();

      final controller = DesktopTrayController(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
      );

      final result = await controller.stopDaemonForQuitForTesting();

      expect(result.ok, isTrue);
      expect(stores.statusStore.daemonReachable, isFalse);
      expect(daemonController.stopCalls, 1);
    },
  );
}

String _expectedTrayIconAsset(String macosAsset) {
  if (Platform.isMacOS) return macosAsset;
  if (Platform.isWindows) return 'assets/tray_icon.ico';
  return 'assets/tray_icon.png';
}

List<String> _labels(DesktopTrayController controller) {
  return controller
      .buildMenuForTesting()
      .items!
      .map((item) => item.label)
      .whereType<String>()
      .toList();
}

Future<DiagnosticsSnapshot> _loadFixtureSnapshot({String? healthStatus}) async {
  final raw = await File('test/fixtures/status_connected.json').readAsString();
  final json = jsonDecode(raw) as Map<String, dynamic>;
  if (healthStatus != null) {
    (json['health'] as Map<String, dynamic>)['status'] = healthStatus;
  }
  return DiagnosticsSnapshot.fromJson(json);
}

Future<_Stores> _makeStores({
  required DiagnosticsApi api,
  DaemonController? daemonController,
}) async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_tray_test_');
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await settingsStore.load();
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    daemonController: daemonController,
  );
  return _Stores(tempDir, settingsStore, statusStore);
}

class _Stores {
  const _Stores(this.tempDir, this.settingsStore, this.statusStore);

  final Directory tempDir;
  final SettingsStore settingsStore;
  final StatusStore statusStore;

  void dispose() {
    statusStore.dispose();
    settingsStore.dispose();
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  }
}

class _FakeDiagnosticsApi implements DiagnosticsApi {
  _FakeDiagnosticsApi({required this.snapshot});

  DiagnosticsSnapshot? snapshot;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => snapshot != null;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    final currentSnapshot = snapshot;
    if (currentSnapshot == null) {
      throw const DiagnosticsApiException('Diagnostics are offline');
    }
    return currentSnapshot;
  }

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => snapshot != null;

  @override
  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) async {
    return SpeedTestResult(
      peerVirtualIp: peerVirtualIp,
      durationMs: duration.inMilliseconds,
      downloadMbps: 0,
      uploadMbps: 0,
      downloadBytes: 0,
      uploadBytes: 0,
    );
  }

  @override
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    int? processId,
    Duration timeout = const Duration(seconds: 30),
  }) async => throw UnimplementedError();

  @override
  Future<PeersPageResponse> fetchPeers(
    String diagnosticsUrl, {
    String? cursor,
    int limit = 100,
  }) async => throw UnimplementedError();

  @override
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) async => throw UnimplementedError();

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async =>
      throw UnimplementedError();

  @override
  Future<RouteRepairResponse> repairRoutes(String diagnosticsUrl) async =>
      throw UnimplementedError();

  @override
  void close() {}
}

class _DelayedStopDaemonController extends DaemonController {
  _DelayedStopDaemonController({
    required super.diagnosticsApi,
    required this.stopCompleter,
  });

  final Completer<DaemonCommandResult> stopCompleter;
  var stopCalls = 0;

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) {
    stopCalls += 1;
    return stopCompleter.future;
  }
}

class _CountingStopDaemonController extends DaemonController {
  _CountingStopDaemonController({required super.diagnosticsApi});

  var stopCalls = 0;

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    stopCalls += 1;
    return const DaemonCommandResult(ok: true, message: 'fake stop');
  }
}

class _OfflineAfterFailedStopDaemonController extends DaemonController {
  _OfflineAfterFailedStopDaemonController({
    required super.diagnosticsApi,
    required this.api,
  });

  final _FakeDiagnosticsApi api;
  var stopCalls = 0;

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    stopCalls += 1;
    api.snapshot = null;
    return const DaemonCommandResult(ok: false, message: 'already stopped');
  }
}
