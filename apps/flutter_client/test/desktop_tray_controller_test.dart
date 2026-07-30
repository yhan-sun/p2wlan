import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/desktop_tray_controller.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';

void main() {
  test('desktop tray builds the primary control menu', () async {
    final tempDir = await Directory.systemTemp.createTemp('p2wlan_tray_test_');
    addTearDown(() {
      if (tempDir.existsSync()) {
        tempDir.deleteSync(recursive: true);
      }
    });

    final settingsStore = SettingsStore(
      settingsFile: File('${tempDir.path}/settings.json'),
    );
    final statusStore = StatusStore(
      settingsStore: settingsStore,
      diagnosticsApi: DiagnosticsApi(),
    );
    addTearDown(statusStore.dispose);
    addTearDown(settingsStore.dispose);

    await settingsStore.load();
    final controller = DesktopTrayController(
      settingsStore: settingsStore,
      statusStore: statusStore,
    );

    final menuItems = controller.buildMenuForTesting().items!;
    final labels = menuItems
        .map((item) => item.label)
        .whereType<String>()
        .toList();

    expect(labels, contains('Open console'));
    expect(labels, contains('Start P2WLAN'));
    expect(labels, contains('Stop P2WLAN'));
    expect(labels, contains('Open logs'));
    expect(labels, contains('Quit P2WLAN'));
  });
}
