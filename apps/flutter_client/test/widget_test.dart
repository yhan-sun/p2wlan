import 'dart:io';

import 'package:flutter/foundation.dart'
    show debugDefaultTargetPlatformOverride;
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';
import 'package:p2wlan_flutter_client/features/diagnostics/diagnostics_page.dart';
import 'package:p2wlan_flutter_client/features/nodes/nodes_page.dart';
import 'package:p2wlan_flutter_client/features/settings/settings_page.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_nav_rail.dart';
import 'package:p2wlan_flutter_client/shared/widgets/desktop_sidebar.dart';
import 'package:p2wlan_flutter_client/shared/widgets/status_badge.dart';

void main() {
  testWidgets('renders the P2WLAN client shell in Chinese by default', (
    tester,
  ) async {
    await _pumpTestApp(tester);

    expect(find.text('首页'), findsWidgets);
    expect(find.text('离线'), findsWidgets);
  });

  testWidgets('opens settings and shows diagnostics URL field', (tester) async {
    await _pumpTestApp(tester);

    await tester.tap(find.text('设置').last);
    await tester.pump();

    // Diagnostics lives in the collapsed Developer section (progressive
    // disclosure), so it is revealed before asserting on the URL field.
    expect(find.text('开发与诊断'), findsOneWidget);
    await tester.ensureVisible(find.text('开发与诊断'));
    await tester.pump();
    await tester.tap(find.text('开发与诊断'));
    await tester.pump(const Duration(milliseconds: 250));

    expect(find.text('诊断 URL'), findsWidgets);
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
    expect(find.text('Developer & Diagnostics'), findsOneWidget);
    await tester.ensureVisible(find.text('Developer & Diagnostics'));
    await tester.pump();
    await tester.tap(find.text('Developer & Diagnostics'));
    await tester.pump(const Duration(milliseconds: 250));
    expect(find.text('Diagnostics URL'), findsWidgets);
  });

  testWidgets('uses three-tier responsive navigation', (tester) async {
    // Compact phone: exactly three bottom destinations, no rail.
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await _pumpTestApp(tester);

    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.byType(AppNavRail), findsNothing);
    expect(find.byType(DesktopSidebar), findsNothing);
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(3),
    );
    expect(find.text('首页'), findsWidgets);
    expect(find.text('设备'), findsWidgets);
    expect(find.text('设置'), findsOneWidget);
    // No permanent "More" destination.
    expect(find.text('更多'), findsNothing);
    // Mobile: no top-bar status badge; only the hero carries one.
    expect(find.byType(StatusBadge), findsOneWidget);

    // Medium tablet / small window: a labeled rail with the four primary
    // sections.
    tester.view.physicalSize = const Size(700, 1000);
    await tester.pump();
    await tester.pump();

    expect(find.byType(AppNavRail), findsOneWidget);
    expect(
      tester.widget<AppNavRail>(find.byType(AppNavRail)).iconOnly,
      isFalse,
    );
    expect(find.byType(NavigationBar), findsNothing);
    expect(find.text('首页'), findsOneWidget);
    expect(find.text('设备'), findsOneWidget);
    expect(find.text('故障排查'), findsOneWidget);
    expect(find.text('设置'), findsOneWidget);
    expect(find.text('隧道'), findsNothing);
    // Medium has no sidebar footer: the top bar keeps its status badge.
    expect(find.byType(StatusBadge), findsNWidgets(2));

    // Expanded desktop: real sidebar with brand header and status footer.
    tester.view.physicalSize = const Size(1280, 900);
    await tester.pump();
    await tester.pump();

    expect(find.byType(AppNavRail), findsNothing);
    expect(find.byType(DesktopSidebar), findsOneWidget);
    expect(find.text('P2WLAN'), findsWidgets);
    expect(find.text('首页'), findsOneWidget);
    expect(find.text('设备'), findsOneWidget);
    expect(find.text('故障排查'), findsOneWidget);
    expect(find.text('设置'), findsOneWidget);
    expect(find.text('隧道'), findsNothing);
    // Sidebar status footer renders (daemon is offline in this harness), and
    // the top bar no longer duplicates it: only the hero badge remains.
    expect(find.text('无法连接本地服务'), findsOneWidget);
    expect(find.byType(StatusBadge), findsOneWidget);
  });

  testWidgets(
    'mobile overflow opens troubleshooting with exactly three destinations',
    (tester) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await _pumpTestApp(tester);

      expect(find.byType(DashboardPage), findsOneWidget);

      await tester.tap(find.byIcon(Icons.more_horiz_rounded));
      await tester.pumpAndSettle();

      expect(find.text('故障排查'), findsOneWidget);

      await tester.tap(find.text('故障排查'));
      await tester.pumpAndSettle();

      expect(find.byType(DiagnosticsPage), findsOneWidget);
      // The bottom bar stays at exactly three destinations — no fake fourth
      // tab, no More destination.
      expect(find.byType(NavigationBar), findsOneWidget);
      expect(
        find.descendant(
          of: find.byType(NavigationBar),
          matching: find.byType(NavigationDestination),
        ),
        findsNWidgets(3),
      );
      expect(find.text('更多'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('troubleshooting stays open across viewport changes', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await _pumpTestApp(tester);

    // Open troubleshooting from the mobile overflow menu.
    await tester.tap(find.byIcon(Icons.more_horiz_rounded));
    await tester.pumpAndSettle();
    await tester.tap(find.text('故障排查'));
    await tester.pumpAndSettle();
    expect(find.byType(DiagnosticsPage), findsOneWidget);

    // Grow to Medium: troubleshooting is a primary rail destination and the
    // page must remain open.
    tester.view.physicalSize = const Size(700, 1000);
    await tester.pump();
    await tester.pump();
    expect(find.byType(AppNavRail), findsOneWidget);
    expect(find.byType(NavigationBar), findsNothing);
    expect(find.byType(DiagnosticsPage), findsOneWidget);

    // Grow to Expanded: sidebar layout, same section.
    tester.view.physicalSize = const Size(1280, 900);
    await tester.pump();
    await tester.pump();
    expect(find.byType(DesktopSidebar), findsOneWidget);
    expect(find.byType(DiagnosticsPage), findsOneWidget);
    expect(find.text('无法连接本地服务'), findsOneWidget);

    // Shrink back to Medium then Compact: section survives, bottom bar is
    // still exactly three destinations, and a primary destination can be
    // reached again.
    tester.view.physicalSize = const Size(700, 1000);
    await tester.pump();
    await tester.pump();
    expect(find.byType(DiagnosticsPage), findsOneWidget);

    tester.view.physicalSize = const Size(390, 844);
    await tester.pump();
    await tester.pump();
    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.byType(DiagnosticsPage), findsOneWidget);
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(3),
    );

    await tester.tap(find.text('首页').last);
    await tester.pumpAndSettle();
    expect(find.byType(DashboardPage), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('viewport transitions keep the current section', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await _pumpTestApp(tester);
    expect(find.byType(DashboardPage), findsOneWidget);

    // 390 → 700: Devices stays open under the rail.
    await tester.tap(find.text('设备'));
    await tester.pumpAndSettle();
    expect(find.byType(NodesPage), findsOneWidget);

    tester.view.physicalSize = const Size(700, 1000);
    await tester.pump();
    await tester.pump();
    expect(find.byType(NodesPage), findsOneWidget);
    expect(find.byType(AppNavRail), findsOneWidget);

    // 700 → 1280: Troubleshooting via the rail, then back to Home via the
    // sidebar.
    await tester.tap(find.text('故障排查'));
    await tester.pumpAndSettle();
    expect(find.byType(DiagnosticsPage), findsOneWidget);

    tester.view.physicalSize = const Size(1280, 900);
    await tester.pump();
    await tester.pump();
    expect(find.byType(DiagnosticsPage), findsOneWidget);
    expect(find.byType(DesktopSidebar), findsOneWidget);

    await tester.tap(find.text('首页'));
    await tester.pumpAndSettle();
    expect(find.byType(DashboardPage), findsOneWidget);

    // 1280 → 700: Settings via the rail.
    await tester.tap(find.text('设置'));
    await tester.pumpAndSettle();
    expect(find.byType(SettingsPage), findsOneWidget);

    tester.view.physicalSize = const Size(700, 1000);
    await tester.pump();
    await tester.pump();
    expect(find.byType(SettingsPage), findsOneWidget);

    // 700 → 390: section survives, three-item bottom bar.
    tester.view.physicalSize = const Size(390, 844);
    await tester.pump();
    await tester.pump();
    expect(find.byType(SettingsPage), findsOneWidget);
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(3),
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('compact desktop keeps a rail instead of the phone bottom bar', (
    tester,
  ) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
    tester.view.physicalSize = const Size(500, 800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await _pumpTestApp(tester);

    expect(find.byType(AppNavRail), findsOneWidget);
    expect(tester.widget<AppNavRail>(find.byType(AppNavRail)).iconOnly, isTrue);
    expect(find.byType(NavigationBar), findsNothing);
    expect(find.byType(NavigationDestination), findsNothing);
    expect(find.byIcon(Icons.more_horiz_rounded), findsNothing);

    // Must be restored inside the test body: the framework asserts that
    // foundation debug variables are unset before it runs tear-downs.
    debugDefaultTargetPlatformOverride = null;
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
    if (find.text('首页').evaluate().isNotEmpty ||
        find.text('登录控制面后启动本机 TUN').evaluate().isNotEmpty) {
      return;
    }
  }
}
