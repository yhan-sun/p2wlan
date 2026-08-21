part of '../p15_widget_test.dart';

void _registerFinalRegressionTests() {
  final elevationPreflight = PermissionPreflight(
    platform: 'macOS',
    state: PermissionPreflightState.elevationRequired,
    canCreateTun: false,
    canModifyRoutes: false,
    elevationSupported: true,
    reasonCode: 'elevation_required',
    message: '启动 TUN 时需要管理员授权；中文 raw message。',
    checks: [
      PermissionCheck(
        label: '有效用户权限（中文 label）',
        status: 'fail',
        detail: '当前是普通用户，需要授权（中文 detail）。',
        code: 'euid',
      ),
      PermissionCheck(
        label: 'TUN 设备节点',
        status: 'warn',
        detail: 'macOS 动态创建 utun。',
        code: 'tun_node',
      ),
    ],
  );
  const satisfiedPreflight = PermissionPreflight(
    platform: 'macOS',
    state: PermissionPreflightState.satisfied,
    canCreateTun: true,
    canModifyRoutes: true,
    elevationSupported: true,
    reasonCode: 'ready',
    message: '权限已满足。',
    checks: [
      PermissionCheck(
        label: 'Effective user permissions',
        status: 'pass',
        detail: 'ok',
        code: 'euid',
      ),
    ],
  );

  // --- Permission locale: Onboarding ---
  for (final (name, code, expectCjk, englishHint, chineseHint) in [
    ('English', 'en', false, 'Administrator authorization', ''),
    ('Chinese', 'zh-Hans', true, '', '管理员授权'),
  ]) {
    testWidgets('Onboarding permission step $name locale has no leak', (
      tester,
    ) async {
      final stores = await _permissionStepStores(
        tester,
        preflight: elevationPreflight,
      );
      addTearDown(stores.dispose);
      await tester.pumpWidget(
        _localeHost(
          tester,
          code,
          OnboardingPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
            capabilities: PlatformCapabilities.fromPlatform('macos'),
            permissionCheck: () async => elevationPreflight,
            onCompleted: () {},
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text(code == 'en' ? 'Permission' : '权限'), findsWidgets);
      if (!expectCjk) {
        _expectNoCjk(tester, page: 'Onboarding ($name)');
        expect(find.textContaining(englishHint), findsWidgets);
      } else {
        expect(find.textContaining(chineseHint), findsWidgets);
      }
      expect(tester.takeException(), isNull);
    });
  }

  // --- Permission locale: Diagnostics Advanced ---
  testWidgets('Diagnostics Advanced platform permissions is locale-safe', (
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
      _localeHost(
        tester,
        'en',
        DiagnosticsPage(
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: () async => elevationPreflight,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _expandAdvanced(tester);

    expect(find.text('Platform permissions'), findsOneWidget);
    _expectNoCjk(tester, page: 'Diagnostics Advanced');
    // Localized check titles from machine codes, not raw Chinese labels.
    expect(find.text('Effective user permissions'), findsOneWidget);
    expect(find.text('TUN device node'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  // --- Onboarding completion failure (localized generic) ---
  testWidgets('Onboarding completion failure shows localized generic error', (
    tester,
  ) async {
    final stores = await _completionStepStores(tester);
    addTearDown(stores.dispose);
    await tester.pumpWidget(
      _localeHost(
        tester,
        'en',
        OnboardingPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: () async => satisfiedPreflight,
          onCompleted: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Finish'));
    await tester.pumpAndSettle();

    expect(
      find.text('Could not finish local setup. Please try again.'),
      findsOneWidget,
    );
    expect(find.textContaining('SUPER_SECRET'), findsNothing);
    expect(find.textContaining('FileSystemException'), findsNothing);
    expect(find.textContaining('Exception'), findsNothing);
    expect(stores.settingsStore.settings.onboardingCompleted, isFalse);
    expect(tester.takeException(), isNull);
  });

  // --- Onboarding daemon start failure (localized generic) ---
  testWidgets('Onboarding daemon start failure is localized', (tester) async {
    final stores = await _permissionStepStores(
      tester,
      preflight: elevationPreflight,
      failingDaemon: true,
    );
    addTearDown(stores.dispose);
    await tester.pumpWidget(
      _localeHost(
        tester,
        'en',
        OnboardingPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: () async => elevationPreflight,
          onCompleted: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Grant & continue'));
    await tester.pumpAndSettle();

    expect(
      find.text('Could not start P2WLAN. Check permissions and try again.'),
      findsOneWidget,
    );
    expect(find.textContaining('SocketException'), findsNothing);
    expect(find.textContaining('SECRET'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  // --- Network & route diagnostics (Troubleshooting Advanced) ---
  testWidgets('Troubleshooting desktop shows local route actions', (
    tester,
  ) async {
    final stores = await _smokeStores(tester);
    addTearDown(stores.dispose);
    await tester.pumpWidget(
      _localeHost(
        tester,
        'en',
        DiagnosticsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _expandAdvanced(tester);

    expect(find.text('Check routes'), findsOneWidget);
    expect(find.text('Repair routes'), findsOneWidget);
    expect(
      find.text('Restart network service (brief disconnect)'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'Troubleshooting android hides local actions and never verifies routes',
    (tester) async {
      final api = _FakeDiagnosticsApi(
        health: true,
        snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      );
      final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
      addTearDown(stores.dispose);
      await stores.statusStore.refresh();
      // The store refresh calls verifyRoutes itself; baseline it so we can
      // prove the page (on android) does not issue an additional local check.
      final baselineVerifyCount = api.verifyRoutesCount;

      await tester.pumpWidget(
        _localeHost(
          tester,
          'en',
          DiagnosticsPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
            capabilities: PlatformCapabilities.fromPlatform('android'),
            permissionCheck: _noopPermissionCheck,
            logPreviewLoader: _noopLogPreviewLoader,
          ),
        ),
      );
      await tester.pumpAndSettle();
      await _expandAdvanced(tester);

      expect(find.text('Check routes'), findsNothing);
      expect(find.text('Repair routes'), findsNothing);
      expect(
        find.text('Restart network service (brief disconnect)'),
        findsNothing,
      );
      expect(api.verifyRoutesCount, baselineVerifyCount);
      expect(tester.takeException(), isNull);
    },
  );

  // --- Network route repair raw errors ---
  testWidgets('Troubleshooting route repair failure is localized', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: missingRoutesFixture,
      repairRoutesError: Exception('SUPER_SECRET'),
    );
    final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _localeHost(
        tester,
        'en',
        DiagnosticsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _expandAdvanced(tester);
    tester
        .widget<OutlinedButton>(
          find.widgetWithText(OutlinedButton, 'Repair routes'),
        )
        .onPressed!();
    await tester.pumpAndSettle();

    expect(
      find.text('Could not repair routes. Please try again.'),
      findsOneWidget,
    );
    expect(find.textContaining('SUPER_SECRET'), findsNothing);
    expect(find.textContaining('Exception'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Troubleshooting restart failure is localized', (tester) async {
    final stores = await _permissionStepStores(
      tester,
      preflight: satisfiedPreflight,
      failingDaemon: true,
      running: true,
    );
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _localeHost(
        tester,
        'en',
        DiagnosticsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _expandAdvanced(tester);
    tester
        .widget<TextButton>(
          find.widgetWithText(
            TextButton,
            'Restart network service (brief disconnect)',
          ),
        )
        .onPressed!();
    await tester.pumpAndSettle();

    expect(
      find.text('Could not restart the network service. Please try again.'),
      findsOneWidget,
    );
    expect(find.textContaining('SocketException'), findsNothing);
    expect(find.textContaining('SECRET'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  // --- Async lifecycle: dispose mid-rebuild ---
  testWidgets('disposing network section mid-restart does not throw', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    final hanging = _HangingDaemonController(api);
    final stores = (await tester.runAsync(
      () => _makeStores(api: api, daemonController: hanging),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _localeHost(
        tester,
        'en',
        DiagnosticsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _expandAdvanced(tester);

    tester
        .widget<TextButton>(
          find.widgetWithText(
            TextButton,
            'Restart network service (brief disconnect)',
          ),
        )
        .onPressed!();
    await tester.pump();

    // Dispose the page while the daemon stop is still in flight, then let it
    // complete; the mounted guards must prevent any post-dispose setState.
    await tester.pumpWidget(const SizedBox.shrink());
    hanging.completeAll();
    await tester.pump();

    expect(tester.takeException(), isNull);
  });

  // --- 390 responsive ---
  for (final (page, builder) in [
    (
      'Onboarding',
      (WidgetTester t, String code, _Stores s) => _localeHost(
        t,
        code,
        OnboardingPage(
          settingsStore: s.settingsStore,
          statusStore: s.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: () async => elevationPreflight,
          onCompleted: () {},
        ),
      ),
    ),
    (
      'Troubleshooting',
      (WidgetTester t, String code, _Stores s) => _localeHost(
        t,
        code,
        DiagnosticsPage(
          settingsStore: s.settingsStore,
          statusStore: s.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    ),
  ]) {
    for (final code in ['en', 'zh-Hans']) {
      testWidgets('$page 390x844 fits $code', (tester) async {
        await tester.binding.setSurfaceSize(const Size(390, 844));
        addTearDown(() => tester.binding.setSurfaceSize(null));
        final stores = await _smokeStores(tester);
        addTearDown(stores.dispose);
        await tester.pumpWidget(builder(tester, code, stores));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      });
    }
  }
}

/// A store on the permission step (manual mode, daemon down, elevation
/// preflight), optionally with a failing daemon controller.
Future<_Stores> _permissionStepStores(
  WidgetTester tester, {
  required PermissionPreflight preflight,
  bool failingDaemon = false,
  bool running = false,
}) async {
  final api = _FakeDiagnosticsApi(
    health: running,
    snapshot: running ? (await tester.runAsync(_loadFixtureSnapshot)) : null,
  );
  final stores = (await tester.runAsync(
    () => _makeStores(
      api: api,
      manualMode: true,
      daemonController: failingDaemon
          ? _FailingDaemonController(api)
          : _FakeDaemonController(api),
    ),
  ))!;
  if (running) await stores.statusStore.refresh();
  return stores;
}

/// A store on the completion step (manual mode, satisfied permissions, daemon
/// healthy, virtual IP + peers present) whose persistence throws on save.
Future<_Stores> _completionStepStores(WidgetTester tester) async {
  final api = _FakeDiagnosticsApi(
    health: true,
    snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
  );
  final tempDir = await tester.runAsync(
    () => Directory.systemTemp.createTemp('p2wlan_completion_test_'),
  );
  final tokenRepository = _ThrowingCompletionTokenRepository();
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir!.path}/settings.json'),
    tokenRepository: tokenRepository,
  );
  await tester.runAsync(settingsStore.load);
  await tester.runAsync(
    () => settingsStore.updateSettings(
      settingsStore.settings.copyWith(
        languageCode: AppLanguage.english.code,
        manualMode: true,
      ),
    ),
  );
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    daemonController: _FakeDaemonController(api),
    autoRefreshInterval: const Duration(minutes: 5),
  );
  await statusStore.refresh();
  return _Stores(tempDir, settingsStore, statusStore, tokenRepository);
}

class _FailingDaemonController extends DaemonController {
  _FailingDaemonController(DiagnosticsApi api) : super(diagnosticsApi: api);

  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    return const DaemonCommandResult(
      ok: false,
      message: 'Daemon operation failed: SocketException SECRET',
    );
  }

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    return const DaemonCommandResult(
      ok: false,
      message: 'Daemon operation failed: SocketException SECRET',
    );
  }
}

class _ThrowingCompletionTokenRepository implements SecureTokenRepository {
  var _writeCount = 0;

  @override
  Future<String?> read() async => null;

  @override
  Future<void> write(String token) async {
    _writeCount += 1;
    // The first write happens during test setup (settings updated with the
    // in-memory token); only the completion-persistence write fails.
    if (_writeCount > 1) {
      throw Exception('SUPER_SECRET');
    }
  }

  @override
  Future<void> clear() async {}
}

/// Daemon controller whose start/stop stay pending until [completeAll].
class _HangingDaemonController extends DaemonController {
  _HangingDaemonController(DiagnosticsApi api) : super(diagnosticsApi: api);

  final _stop = Completer<DaemonCommandResult>();
  final _start = Completer<DaemonCommandResult>();

  @override
  Future<DaemonCommandResult> start(AppSettings settings) => _start.future;

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) => _stop.future;

  void completeAll() {
    if (!_stop.isCompleted) {
      _stop.complete(const DaemonCommandResult(ok: true, message: 'stopped'));
    }
    if (!_start.isCompleted) {
      _start.complete(const DaemonCommandResult(ok: true, message: 'started'));
    }
  }
}
