import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';

void main() {
  testWidgets('renders the P2WLAN client shell in Chinese by default', (
    tester,
  ) async {
    await _pumpTestApp(tester);

    expect(find.text('仪表盘'), findsWidgets);
    expect(find.text('离线'), findsWidgets);
  });

  testWidgets('opens settings and shows diagnostics URL field', (tester) async {
    await _pumpTestApp(tester);

    await tester.tap(find.text('设置').last);
    await tester.pump();

    expect(find.text('诊断端点'), findsWidgets);
    expect(find.text('守护进程控制'), findsOneWidget);
  });

  testWidgets('switches the shell language from Chinese to English', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await _pumpTestApp(tester);

    await tester.tap(find.text('设置').last);
    await tester.pump(const Duration(milliseconds: 250));
    await tester.tap(find.text('简体中文').last);
    await tester.pump(const Duration(milliseconds: 250));
    await tester.tap(find.text('English').last);
    await tester.runAsync(() async {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    });
    await tester.pump();

    expect(find.text('Settings'), findsWidgets);
    expect(find.text('Diagnostics endpoint'), findsWidgets);
    expect(find.text('Daemon control'), findsOneWidget);
  });

  testWidgets('uses compact navigation below the desktop rail breakpoint', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(700, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await _pumpTestApp(tester);

    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.byType(NavigationRail), findsNothing);
  });
}

Future<void> _pumpTestApp(WidgetTester tester) async {
  final tempDir = await tester.runAsync(
    () => Directory.systemTemp.createTemp('p2wlan_app_widget_test_'),
  );
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir!.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await tester.runAsync(() async {
    await settingsStore.load();
    // Complete onboarding so these shell tests reach the main UI (the
    // onboarding flow is covered by onboarding_page_test.dart).
    await settingsStore.updateSettings(
      const AppSettings(manualMode: true, onboardingCompleted: true),
    );
  });
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
  for (var attempt = 0; attempt < 20; attempt += 1) {
    await tester.runAsync(() async {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    });
    await tester.pump();
    if (find.text('仪表盘').evaluate().isNotEmpty ||
        find.text('登录控制面后启动本机 TUN').evaluate().isNotEmpty) {
      return;
    }
  }
}
