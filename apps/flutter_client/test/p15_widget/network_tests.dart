part of '../p15_widget_test.dart';

/// Network & route diagnostics migrated from the deleted Tunnels page into
/// Troubleshooting → Advanced. Every former Tunnels behavior keeps coverage
/// here — nothing was dropped by removing the standalone page.
void _registerNetworkTests() {
  const macosCaps = PlatformCapabilities(
    canControlLocalDaemon: true,
    canRequestElevation: true,
    canVerifyRoutes: true,
    canRepairRoutes: true,
    canOpenLocalLogs: true,
    canCreateSupportBundle: true,
    canUseSystemTray: true,
    canActAsLocalVpnNode: true,
    canManageRemoteDevices: true,
  );

  const noRepairCaps = PlatformCapabilities(
    canControlLocalDaemon: true,
    canRequestElevation: true,
    canVerifyRoutes: true,
    canRepairRoutes: false,
    canOpenLocalLogs: true,
    canCreateSupportBundle: true,
    canUseSystemTray: true,
    canActAsLocalVpnNode: true,
    canManageRemoteDevices: true,
  );

  const noRestartCaps = PlatformCapabilities(
    canControlLocalDaemon: false,
    canRequestElevation: true,
    canVerifyRoutes: true,
    canRepairRoutes: true,
    canOpenLocalLogs: true,
    canCreateSupportBundle: true,
    canUseSystemTray: true,
    canActAsLocalVpnNode: true,
    canManageRemoteDevices: true,
  );

  Future<_Stores> pumpNetworkPage(
    WidgetTester tester, {
    required DiagnosticsApi api,
    PlatformCapabilities capabilities = macosCaps,
    DaemonController? daemonController,
    bool expandAdvanced = true,
  }) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: api, daemonController: daemonController),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DiagnosticsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: capabilities,
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    if (expandAdvanced) {
      await _expandAdvanced(tester);
    }
    return stores;
  }

  const installedRoutes = _fakeRoutes;
  const missingRoutes = missingRoutesFixture;
  const conflictRoutes = conflictRoutesFixture;
  const noChangeRepair = noChangeRepairFixture;

  testWidgets(
    'verify route installed: authoritative state, no guessed health',
    (tester) async {
      final api = _FakeDiagnosticsApi(
        health: true,
        snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
        routes: installedRoutes,
      );
      await pumpNetworkPage(tester, api: api);

      // The route badge is green only because the daemon said "installed".
      expect(find.text('Installed'), findsOneWidget);
      expect(find.text('Check routes'), findsOneWidget);
      expect(
        find.textContaining('Authoritative state: installed.'),
        findsOneWidget,
      );
      expect(find.text('Missing'), findsNothing);
      expect(find.text('Conflict'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('verify route missing: never inferred as healthy', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: missingRoutes,
    );
    await pumpNetworkPage(tester, api: api);

    expect(find.text('Missing'), findsOneWidget);
    expect(
      find.textContaining('Authoritative state: missing.'),
      findsOneWidget,
    );
    // Repair becomes a prominent action when the route is missing.
    expect(find.text('Repair routes'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'failed route recheck expires the old success and retains its time',
    (tester) async {
      final api = _FakeDiagnosticsApi(
        health: true,
        snapshot: await tester.runAsync(_loadFixtureSnapshot),
        routes: installedRoutes,
      );
      await pumpNetworkPage(tester, api: api);
      final checkedAt = tester
          .widgetList<Text>(find.byType(Text))
          .map((text) => text.data)
          .whereType<String>()
          .firstWhere(
            (value) =>
                RegExp(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
                    .hasMatch(value),
          );
      api.verifyRoutesError = Exception('SECRET');
      await _tapVisible(tester, find.text('Check routes'));
      expect(find.text('Installed'), findsNothing);
      expect(find.text('Unknown (unverified)'), findsOneWidget);
      expect(find.text('No fix needed'), findsNothing);
      expect(find.text(checkedAt), findsOneWidget);
      expect(
        find.textContaining('Previous results do not confirm'),
        findsOneWidget,
      );
      expect(find.textContaining('SECRET'), findsNothing);
      await tester.pump(const Duration(seconds: 6));
      expect(
        find.textContaining('Previous results do not confirm'),
        findsOneWidget,
      );
      api.verifyRoutesError = null;
      api.routes = missingRoutes;
      await _tapVisible(tester, find.text('Check routes'));
      expect(find.text('Missing'), findsOneWidget);
      expect(
        find.textContaining('Previous results do not confirm'),
        findsNothing,
      );
    },
  );

  testWidgets('route result from an old account cannot replace the new check', (
    tester,
  ) async {
    final api = _DeferredRouteDiagnosticsApi(
      snapshot: (await tester.runAsync(_loadFixtureSnapshot))!,
    );
    final stores = await pumpNetworkPage(tester, api: api);
    final pending = Completer<RoutesResponse>();
    api.nextVerification = pending.future;
    await _tapVisibleNoSettle(tester, find.text('Check routes'));
    api.routes = missingRoutes;
    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(authToken: 'replacement-token'),
      ),
    );
    await tester.pumpAndSettle();
    // The account switch deliberately requires a fresh local start before a
    // replacement runtime may publish its route result.
    await tester.runAsync(stores.statusStore.startDaemon);
    await tester.pumpAndSettle();
    await _tapVisible(tester, find.text('Check routes'));
    pending.complete(installedRoutes);
    await tester.pumpAndSettle();
    expect(find.text('Missing'), findsOneWidget);
    expect(find.text('Installed'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('verify route conflict surfaces actual interface', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: conflictRoutes,
    );
    await pumpNetworkPage(tester, api: api);

    expect(find.text('Conflict'), findsOneWidget);
    expect(
      find.textContaining('Authoritative state: conflict.'),
      findsOneWidget,
    );
    expect(find.text('en0'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('repair success shows inline confirmation and new state', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: missingRoutes,
    );
    await pumpNetworkPage(tester, api: api);

    // Repair installs the route; the follow-up authoritative verify reflects it.
    api.routes = installedRoutes;
    await _tapVisible(tester, find.text('Repair routes'));

    expect(
      find.text(
        'Route repaired in place (state: installed) without restarting the daemon.',
      ),
      findsOneWidget,
    );
    expect(find.text('Installed'), findsOneWidget);
    final feedback = find
        .ancestor(
          of: find.text(
            'Route repaired in place (state: installed) without restarting the daemon.',
          ),
          matching: find.byType(DecoratedBox),
        )
        .first;
    expect(
      (tester.widget<DecoratedBox>(feedback).decoration as BoxDecoration).color,
      P2WlanColors.light.successSurface,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('repair already installed reports no change', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: installedRoutes,
      repairResult: noChangeRepair,
    );
    await pumpNetworkPage(tester, api: api);

    // Route installed → repair is a low-weight text action, never highlighted.
    expect(find.widgetWithText(TextButton, 'Repair routes'), findsOneWidget);
    expect(find.text('No fix needed'), findsOneWidget);
    await _tapVisible(tester, find.text('Repair routes'));

    expect(
      find.text('Route was already correctly installed; no change needed.'),
      findsOneWidget,
    );
    final feedback = find
        .ancestor(
          of: find.text(
            'Route was already correctly installed; no change needed.',
          ),
          matching: find.byType(DecoratedBox),
        )
        .first;
    expect(
      (tester.widget<DecoratedBox>(feedback).decoration as BoxDecoration).color,
      P2WlanColors.light.neutralSurface,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('repair failure is localized and redacted', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: missingRoutes,
      repairRoutesError: Exception('SUPER_SECRET'),
    );
    await pumpNetworkPage(tester, api: api);

    await _tapVisible(tester, find.text('Repair routes'));

    expect(
      find.text('Could not repair routes. Please try again.'),
      findsOneWidget,
    );
    expect(find.textContaining('SUPER_SECRET'), findsNothing);
    expect(find.textContaining('Exception'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('restart failure is localized and redacted', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    final failing = _FailingDaemonController(api);
    await pumpNetworkPage(tester, api: api, daemonController: failing);

    await _tapVisible(
      tester,
      find.text('Restart network service (brief disconnect)'),
    );
    await tester.pumpAndSettle();

    expect(
      find.text(
        'The default local connection could not be stopped. Starting it again has not been attempted.',
      ),
      findsOneWidget,
    );
    expect(find.textContaining('SocketException'), findsNothing);
    expect(find.textContaining('SECRET'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('restart start failure retries starting without stopping twice', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: await tester.runAsync(_loadFixtureSnapshot),
    );
    final controller = _RetryNetworkDaemonController(api)..startOk = false;
    await pumpNetworkPage(tester, api: api, daemonController: controller);
    await _tapVisible(
      tester,
      find.text('Restart network service (brief disconnect)'),
    );
    expect(controller.stops, 1);
    expect(controller.starts, 1);
    expect(
      find.text(
        'The stop step completed, but the default local connection could not be confirmed as restarted.',
      ),
      findsOneWidget,
    );
    expect(find.text('Retry starting'), findsOneWidget);
    controller.startOk = true;
    await _tapVisible(tester, find.text('Retry starting'));
    expect(controller.stops, 1);
    expect(controller.starts, 2);
    expect(
      find.text('Daemon restarted to reinstall overlay routes.'),
      findsOneWidget,
    );
  });

  testWidgets('restart success reports route reinstall', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    final stores = await pumpNetworkPage(tester, api: api);

    await _tapVisible(
      tester,
      find.text('Restart network service (brief disconnect)'),
    );

    expect(
      find.text('Daemon restarted to reinstall overlay routes.'),
      findsOneWidget,
    );
    final feedback = find.byKey(
      const ValueKey('local-connection-restart-feedback'),
    );
    expect(tester.getSize(feedback).height, lessThanOrEqualTo(52));
    await _tapVisible(
      tester,
      find.byKey(const ValueKey('restart-dismiss-success')),
    );
    expect(feedback, findsNothing);
    expect(stores.statusStore.healthReachable, isTrue);
    expect(tester.takeException(), isNull);
  });

  testWidgets('canVerifyRoutes=false hides verify and never verifies', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(
      tester,
      api: api,
      capabilities: PlatformCapabilities.fromPlatform('ios'),
    );

    expect(find.text('Check routes'), findsNothing);
    expect(find.text('Repair routes'), findsNothing);
    expect(
      find.text('Restart network service (brief disconnect)'),
      findsNothing,
    );
    // The store's own refresh() verifies; the page must not add another one
    // for a platform that cannot perform local route operations.
    expect(api.verifyRoutesCount, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('canRepairRoutes=false hides repair but keeps verify', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(tester, api: api, capabilities: noRepairCaps);

    expect(find.text('Check routes'), findsOneWidget);
    expect(find.text('Repair routes'), findsNothing);
    expect(
      find.text('Restart network service (brief disconnect)'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('canControlLocalDaemon=false hides restart', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(tester, api: api, capabilities: noRestartCaps);

    expect(find.text('Check routes'), findsOneWidget);
    expect(find.text('Repair routes'), findsOneWidget);
    expect(
      find.text('Restart network service (brief disconnect)'),
      findsNothing,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('network rows stay readable on narrow screens', (tester) async {
    await tester.binding.setSurfaceSize(const Size(390, 844));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(tester, api: api);

    expect(find.text('Virtual Adapter'), findsOneWidget);
    expect(find.text('Virtual IP'), findsOneWidget);
    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('192.0.2.10:60207'), findsOneWidget);
    expect(find.text('Check routes'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('dispose mid-restart does not throw', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    final hanging = _HangingDaemonController(api);
    await pumpNetworkPage(tester, api: api, daemonController: hanging);

    await _tapVisibleNoSettle(
      tester,
      find.text('Restart network service (brief disconnect)'),
    );

    await tester.pumpWidget(const SizedBox.shrink());
    hanging.completeAll();
    await tester.pump();

    expect(tester.takeException(), isNull);
  });

  for (final scenario in ['leave', 'endpoint', 'replacement', 'disposed']) {
    final changeOwner = scenario != 'leave';
    testWidgets(
      'diagnostics restart ${scenario == 'endpoint'
          ? 'rejects a changed endpoint'
          : scenario == 'replacement'
          ? 'rejects a replacement owner with the same revision and endpoint'
          : scenario == 'disposed'
          ? 'rejects a disposed store'
          : 'finishes on its original owner'} after leaving',
      (tester) async {
        final api = _FakeDiagnosticsApi(
          health: true,
          snapshot: await tester.runAsync(_loadFixtureSnapshot),
        );
        final controller = _DeferredRestartDaemonController(api);
        final original = await pumpNetworkPage(
          tester,
          api: api,
          daemonController: controller,
        );
        final originalUrl = original.settingsStore.settings.diagnosticsUrl;
        await _tapVisibleNoSettle(
          tester,
          find.text('Restart network service (brief disconnect)'),
        );
        expect(controller.stops, 1);
        expect(controller.starts, 0);
        final replacementApi = _FakeDiagnosticsApi(health: false);
        final replacementController = _RetryNetworkDaemonController(
          replacementApi,
        );
        final replacement = (await tester.runAsync(
          () => _makeStores(
            api: replacementApi,
            daemonController: replacementController,
          ),
        ))!;
        addTearDown(replacement.dispose);
        expect(
          replacement.statusStore.sessionRevision,
          original.statusStore.sessionRevision,
        );
        expect(replacement.settingsStore.settings.diagnosticsUrl, originalUrl);
        await tester.pumpWidget(
          _TestApp(
            child: DiagnosticsPage(
              key: scenario == 'replacement'
                  ? null
                  : const ValueKey('replacement-diagnostics'),
              settingsStore: replacement.settingsStore,
              statusStore: replacement.statusStore,
            ),
          ),
        );
        await tester.pumpAndSettle();
        if (scenario == 'endpoint') {
          await tester.runAsync(
            () => original.settingsStore.updateSettings(
              original.settingsStore.settings.copyWith(
                diagnosticsUrl: 'http://127.0.0.1:39279',
              ),
            ),
          );
        }
        if (scenario == 'disposed') original.statusStore.dispose();
        controller.pendingStop.complete(
          const DaemonCommandResult(ok: true, message: 'stopped'),
        );
        await _waitFor(tester, () => !original.statusStore.daemonBusy);
        await tester.pumpAndSettle();
        expect(controller.starts, changeOwner ? 0 : 1);
        expect(replacementController.starts, 0);
        if (scenario == 'replacement') {
          expect(find.text('Installed'), findsNothing);
          expect(
            find.byKey(const ValueKey('local-connection-restart-feedback')),
            findsNothing,
          );
          expect(
            tester
                .widget<OutlinedButton>(
                  find.widgetWithText(OutlinedButton, 'Check again'),
                )
                .onPressed,
            isNotNull,
          );
        }
        if (!changeOwner) {
          expect(controller.startedSettings.single.diagnosticsUrl, originalUrl);
        }
        expect(tester.takeException(), isNull);
      },
    );
  }
}

class _DeferredRouteDiagnosticsApi extends _FakeDiagnosticsApi {
  _DeferredRouteDiagnosticsApi({required DiagnosticsSnapshot snapshot})
    : super(health: true, snapshot: snapshot);

  Future<RoutesResponse>? nextVerification;

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) {
    final next = nextVerification;
    nextVerification = null;
    return next ?? super.verifyRoutes(diagnosticsUrl);
  }
}

class _RetryNetworkDaemonController extends _FakeDaemonController {
  _RetryNetworkDaemonController(super.api);

  bool startOk = true;
  bool stopOk = true;
  int starts = 0;
  int stops = 0;

  @override
  Future<DaemonCommandResult> start(
    AppSettings settings, {
    int? vpnSettingsRevision,
  }) async {
    starts++;
    return DaemonCommandResult(ok: startOk, message: 'test startup result');
  }

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    stops++;
    return DaemonCommandResult(ok: stopOk, message: 'test stop result');
  }
}

class _DeferredRestartDaemonController extends _RetryNetworkDaemonController {
  _DeferredRestartDaemonController(super.api);

  final pendingStop = Completer<DaemonCommandResult>();
  final startedSettings = <AppSettings>[];

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) {
    stops++;
    return pendingStop.future;
  }

  @override
  Future<DaemonCommandResult> start(
    AppSettings settings, {
    int? vpnSettingsRevision,
  }) {
    startedSettings.add(settings);
    return super.start(settings, vpnSettingsRevision: vpnSettingsRevision);
  }
}

/// Scrolls [finder] into view and taps it, settling the advanced sections.
Future<void> _tapVisible(WidgetTester tester, Finder finder) async {
  await tester.ensureVisible(finder);
  await tester.pumpAndSettle();
  await tester.tap(finder);
  await tester.pumpAndSettle();
}

/// Same as [_tapVisible] but without settling: used while a daemon operation
/// stays in flight (e.g. the dispose mid-restart test).
Future<void> _tapVisibleNoSettle(WidgetTester tester, Finder finder) async {
  await tester.ensureVisible(finder);
  await tester.pump();
  await tester.tap(finder);
  await tester.pump();
}

const missingRoutesFixture = RoutesResponse(
  contractVersion: 1,
  interfaceName: 'p2wlan0',
  mtu: 1420,
  healthy: false,
  conflictCount: 0,
  entries: [
    RouteEntryResponse(
      cidr: '10.20.0.0/16',
      expectedInterface: 'p2wlan0',
      actualInterface: null,
      state: 'missing',
      owned: true,
    ),
  ],
);

const conflictRoutesFixture = RoutesResponse(
  contractVersion: 1,
  interfaceName: 'p2wlan0',
  mtu: 1420,
  healthy: false,
  conflictCount: 1,
  entries: [
    RouteEntryResponse(
      cidr: '10.20.0.0/16',
      expectedInterface: 'p2wlan0',
      actualInterface: 'en0',
      state: 'conflict',
      owned: false,
    ),
  ],
);

const noChangeRepairFixture = RouteRepairResponse(
  contractVersion: 1,
  cidr: '10.20.0.0/16',
  changed: false,
  attempted: true,
  before: 'installed',
  after: 'installed',
  reason: 'already installed',
  restartedDaemon: false,
);
