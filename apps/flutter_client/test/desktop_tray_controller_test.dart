import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/desktop_tray_controller.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
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

    expect(labels, contains('Open console'));
    expect(labels, contains('Start P2WLAN'));
    expect(labels, isNot(contains('Stop P2WLAN')));
    expect(labels, contains('Open logs'));
    expect(labels, contains('Quit P2WLAN'));
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

    expect(labels, contains('Stop P2WLAN'));
    expect(labels, isNot(contains('Start P2WLAN')));
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

Future<_Stores> _makeStores({required DiagnosticsApi api}) async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_tray_test_');
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
  );
  await settingsStore.load();
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
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
  const _FakeDiagnosticsApi({required this.snapshot});

  final DiagnosticsSnapshot snapshot;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => true;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async =>
      snapshot;

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => true;

  @override
  void close() {}
}
