import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';

const _roomId = 'room-00000000000000000000000000000001';

class _OfflineApi extends DiagnosticsApi {
  Completer<bool>? pendingHealth;
  bool health = false;
  int healthRequests = 0;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async {
    healthRequests++;
    final pending = pendingHealth;
    pendingHealth = null;
    return pending == null ? health : pending.future;
  }

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async =>
      throw const DiagnosticsApiException('Fixture status unavailable');
}

class _Controller extends DaemonController {
  _Controller(DiagnosticsApi api) : super(diagnosticsApi: api);
  final starts = <AppSettings>[];
  Completer<DaemonCommandResult>? pendingStart;

  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    starts.add(settings);
    return pendingStart?.future ??
        const DaemonCommandResult(ok: false, message: 'Fixture start refused');
  }
}

class _Harness {
  _Harness(
    this.directory,
    this.settings,
    this.api,
    this.controller,
    this.status,
  );
  final Directory directory;
  final SettingsStore settings;
  final _OfflineApi api;
  final _Controller controller;
  final StatusStore status;

  void dispose() {
    status.dispose();
    settings.dispose();
    directory.deleteSync(recursive: true);
  }
}

Future<_Harness> _harness({String networkId = 'personal-demo'}) async {
  final directory = await Directory.systemTemp.createTemp('dashboard-entry-');
  final settings = SettingsStore(
    settingsFile: File('${directory.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await settings.load();
  await settings.updateSettings(
    settings.settings.copyWith(
      controlServer: 'https://control.example.com',
      languageCode: 'en',
      deviceName: 'Demo device',
    ),
  );
  await settings.updateSettings(
    settings.settings.copyWith(networkId: networkId),
  );
  final api = _OfflineApi();
  final controller = _Controller(api);
  final status = StatusStore(
    settingsStore: settings,
    diagnosticsApi: api,
    daemonController: controller,
    enableEventPolling: false,
    startupCatalogRefreshTimeout: Duration.zero,
  );
  return _Harness(directory, settings, api, controller, status);
}

Future<void> _pumpHome(
  WidgetTester tester,
  _Harness harness, {
  VoidCallback? onOpenRooms,
  double textScale = 1,
  bool desktopFrame = false,
}) async {
  await tester.pumpWidget(
    MaterialApp(
      theme: AppTheme.lightTheme,
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context)
            .copyWith(textScaler: TextScaler.linear(textScale)),
        child: child!,
      ),
      home: AppStringsScope(
        strings: AppStrings.fromCode('en'),
        child: Scaffold(
          body: Row(
            children: [
              if (desktopFrame) const SizedBox(width: 197),
              Expanded(
                child: DashboardPage(
                  settingsStore: harness.settings,
                  statusStore: harness.status,
                  capabilities: PlatformCapabilities.fromPlatform('linux'),
                  onOpenRooms: onOpenRooms,
                ),
              ),
            ],
          ),
        ),
      ),
    ),
  );
  await tester.pump();
}

void main() {
  testWidgets(
    'stopped Home prioritizes room selection without starting a network',
    (tester) async {
      final harness = (await tester.runAsync(_harness))!;
      addTearDown(harness.dispose);
      await harness.status.refresh();
      var openedRooms = 0;
      await _pumpHome(tester, harness, onOpenRooms: () => openedRooms++);

      expect(find.text('Connect this device'), findsOneWidget);
      expect(find.text('Choose a room'), findsOneWidget);
      expect(find.text('Start personal network'), findsOneWidget);
      expect(find.text('Join or create a room'), findsNothing);
      expect(find.byKey(const Key('home-open-rooms')), findsOneWidget);
      expect(
        tester.widget(find.byKey(const Key('home-open-rooms'))),
        isA<FilledButton>(),
      );
      expect(
        tester.widget(find.byKey(const Key('dashboard-start-button'))),
        isA<OutlinedButton>(),
      );
      final requestsBefore = harness.api.healthRequests;
      await tester.tap(find.byKey(const Key('home-open-rooms')));
      await tester.pump();
      expect(openedRooms, 1);
      expect(harness.controller.starts, isEmpty);
      expect(harness.settings.settings.networkId, 'personal-demo');
      expect(harness.api.healthRequests, requestsBefore);

      await tester.tap(find.byKey(const Key('dashboard-start-button')));
      await tester.pumpAndSettle();
      expect(harness.controller.starts.single.networkId, 'personal-demo');
      expect(openedRooms, 1);
    },
  );

  testWidgets(
    'configured room is never described or started as a personal network',
    (tester) async {
      final harness = (await tester.runAsync(
        () => _harness(networkId: _roomId),
      ))!;
      addTearDown(harness.dispose);
      await harness.status.refresh();
      await _pumpHome(tester, harness, onOpenRooms: () {});

      expect(find.text('Connect configured room'), findsOneWidget);
      expect(find.text('Start personal network'), findsNothing);
      await tester.tap(find.byKey(const Key('dashboard-start-button')));
      await tester.pumpAndSettle();
      expect(harness.controller.starts.single.networkId, _roomId);
      expect(harness.settings.settings.networkId, _roomId);
    },
  );

  testWidgets(
    'Home without a Rooms callback preserves its original start entry',
    (tester) async {
      final harness = (await tester.runAsync(_harness))!;
      addTearDown(harness.dispose);
      await harness.status.refresh();
      await _pumpHome(tester, harness);

      expect(find.text('Bring your devices together'), findsOneWidget);
      expect(find.byKey(const Key('home-open-rooms')), findsNothing);
      expect(
        tester.widget(find.byKey(const Key('dashboard-start-button'))),
        isA<FilledButton>(),
      );
      expect(find.text('Start P2WLAN'), findsOneWidget);
      await tester.tap(find.byKey(const Key('dashboard-start-button')));
      await tester.pumpAndSettle();
      expect(harness.controller.starts, hasLength(1));
    },
  );

  testWidgets(
    'initial detection and pending permission keep configured start disabled',
    (tester) async {
      final harness = (await tester.runAsync(_harness))!;
      addTearDown(harness.dispose);
      final health = Completer<bool>();
      harness.api.pendingHealth = health;
      final refresh = harness.status.refresh(silent: true);
      await _pumpHome(tester, harness, onOpenRooms: () {});
      expect(
        tester
            .widget<OutlinedButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNull,
      );
      expect(harness.controller.starts, isEmpty);

      health.complete(false);
      await refresh;
      await tester.pump();
      expect(
        tester
            .widget<OutlinedButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNotNull,
      );
      final start = Completer<DaemonCommandResult>();
      harness.controller.pendingStart = start;
      await tester.tap(find.byKey(const Key('dashboard-start-button')));
      await tester.pump();
      expect(harness.status.daemonBusy, isTrue);
      expect(
        tester
            .widget<OutlinedButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNull,
      );
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(harness.controller.starts, hasLength(1));
      start.complete(
        const DaemonCommandResult(ok: false, message: 'Fixture failure'),
      );
      await tester.pumpAndSettle();
      expect(harness.status.daemonBusy, isFalse);
      expect(harness.controller.starts, hasLength(1));
      expect(find.text('Start personal network'), findsOneWidget);
    },
  );

  testWidgets('unreadable runtime keeps recovery and a separate Rooms entry', (
    tester,
  ) async {
    final harness = (await tester.runAsync(_harness))!;
    addTearDown(harness.dispose);
    harness.api.health = true;
    await harness.status.refresh();
    var openedRooms = false;
    await _pumpHome(tester, harness, onOpenRooms: () => openedRooms = true);
    expect(find.text('Status unavailable'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.text('Join or create a room'), findsOneWidget);
    await tester.tap(find.byKey(const Key('home-open-rooms')));
    expect(openedRooms, isTrue);
    expect(harness.controller.starts, isEmpty);
  });

  for (final width in [390.0, 800.0]) {
    testWidgets('room connection entry fits $width at 200% text', (
      tester,
    ) async {
      tester.view.physicalSize = Size(width, 900);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final harness = (await tester.runAsync(_harness))!;
      addTearDown(harness.dispose);
      await harness.status.refresh();
      await _pumpHome(
        tester,
        harness,
        onOpenRooms: () {},
        textScale: 2,
        desktopFrame: width >= 800,
      );
      expect(tester.takeException(), isNull);
      await tester.ensureVisible(
        find.byKey(const Key('dashboard-start-button')),
      );
      await tester.pump();
      expect(
        find.byKey(const Key('dashboard-start-button')).hitTestable(),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    });
  }
}
