import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';

void main() {
  testWidgets('renders the read-only console shell', (tester) async {
    await _pumpTestApp(tester);

    expect(find.text('P2WLAN Diagnostics'), findsOneWidget);
    expect(find.text('Dashboard'), findsWidgets);
    expect(find.text('Offline'), findsWidgets);
  });

  testWidgets('opens settings and shows diagnostics URL field', (tester) async {
    await _pumpTestApp(tester);

    await tester.tap(find.text('Settings').last);
    await tester.pump();

    expect(find.text('Diagnostics URL'), findsWidgets);
    expect(find.text('P1 boundary'), findsOneWidget);
  });

  testWidgets('switches the shell language to simplified Chinese', (
    tester,
  ) async {
    await _pumpTestApp(tester);

    await tester.tap(find.text('Settings').last);
    await tester.pump(const Duration(milliseconds: 250));
    await tester.tap(find.text('English').last);
    await tester.pump(const Duration(milliseconds: 250));
    await tester.tap(find.text('简体中文').last);
    await tester.pump(const Duration(milliseconds: 250));

    expect(find.text('设置'), findsWidgets);
    expect(find.text('诊断 URL'), findsWidgets);
    expect(find.text('P1 边界'), findsOneWidget);
  });
}

Future<void> _pumpTestApp(WidgetTester tester) async {
  final tempDir = await tester.runAsync(
    () => Directory.systemTemp.createTemp('p2wlan_app_widget_test_'),
  );
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir!.path}/settings.json'),
  );
  addTearDown(() {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });
  await tester.pumpWidget(
    P2WlanApp(
      initialRefresh: false,
      autoStartPolling: false,
      settingsStore: settingsStore,
    ),
  );
  await _waitForBootstrap(tester);
}

Future<void> _waitForBootstrap(WidgetTester tester) async {
  await tester.runAsync(() async {
    await Future<void>.delayed(const Duration(milliseconds: 50));
  });
  await tester.pump();
}
