part of '../p15_widget_test.dart';

void _registerDiagnosticsTests() {
  testWidgets('healthy page shows clean overview, checks, and no issues', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final clean = _mutateSnapshot(snapshot, _clearPeerErrors);
    final stores = (await tester.runAsync(
      () =>
          _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: clean)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    expect(find.text('P2WLAN is running normally'), findsOneWidget);
    expect(
      find.text('No issues found that need your attention.'),
      findsOneWidget,
    );
    expect(find.text('Health checks'), findsOneWidget);
    expect(find.text('P2WLAN service'), findsOneWidget);
    expect(find.text('Running normally'), findsOneWidget);
    expect(find.text('Control service'), findsOneWidget);
    expect(find.text('connected'), findsOneWidget);
    expect(find.text('Device connections'), findsOneWidget);
    expect(find.text('2 online, no path anomalies'), findsOneWidget);
    expect(find.text('No action needed'), findsWidgets);
    expect(find.text('Advanced diagnostics'), findsOneWidget);

    // Advanced (and everything technical) stays collapsed by default.
    expect(find.text('Platform permissions'), findsNothing);
    expect(find.text('Protocol and MTU'), findsNothing);
    expect(find.text('Critical tasks'), findsNothing);
    expect(find.text('Recent daemon logs'), findsNothing);
    expect(find.text('Raw /status JSON'), findsNothing);
    expect(find.textContaining('GET /health'), findsNothing);
    expect(find.textContaining('GET /status'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('relay disconnected is not an issue when paths are healthy', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final noRelay = _mutateSnapshot(snapshot, (raw) {
      raw['relay_connected'] = false;
      raw['relay_selection'] = {
        'selected_region': null,
        'selected_endpoint': null,
        'selected_connect_latency_ms': null,
        'last_error': null,
      };
      return raw;
    });
    final clean = _mutateSnapshot(noRelay, _clearPeerErrors);
    final stores = (await tester.runAsync(
      () =>
          _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: clean)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _TestApp(
        child: DiagnosticsPage(
          statusStore: stores.statusStore,
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );

    expect(find.text('P2WLAN is running normally'), findsOneWidget);
    expect(find.text('No action needed'), findsWidgets);
    expect(find.textContaining('Relay'), findsNothing);

    // Relay is only described (neutrally) in the advanced runtime details.
    await _expandAdvanced(tester);
    expect(find.text('Runtime details'), findsOneWidget);
    expect(find.text('Relay'), findsOneWidget);
    expect(find.text('not connected'), findsOneWidget);
    expect(find.textContaining('Relay path needs attention'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('advanced section shows runtime details and raw JSON', (
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
        child: DiagnosticsPage(
          statusStore: stores.statusStore,
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );

    await _expandAdvanced(tester);

    expect(find.text('Runtime details'), findsOneWidget);
    expect(find.text('Health endpoint'), findsOneWidget);
    expect(find.text('Status endpoint'), findsOneWidget);
    expect(find.text('Critical tasks'), findsOneWidget);
    expect(find.text('Recent daemon logs'), findsOneWidget);
    expect(find.text('Raw /status JSON'), findsOneWidget);

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
    expect(tester.takeException(), isNull);
  });

  testWidgets('unreachable daemon shows localized unavailable state', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _TestApp(
        child: DiagnosticsPage(
          statusStore: stores.statusStore,
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );

    expect(find.text('Diagnostics unavailable'), findsOneWidget);
    expect(
      find.text('Unable to read the current P2WLAN status. Please try again.'),
      findsOneWidget,
    );
    expect(find.text('Cannot reach the P2WLAN service'), findsOneWidget);
    expect(find.textContaining('SocketException'), findsNothing);
    expect(find.textContaining('ClientException'), findsNothing);
    expect(find.textContaining('GET /health failed'), findsNothing);
    expect(find.textContaining('GET /status skipped'), findsNothing);

    // Advanced still offers redacted endpoint detail.
    await _expandAdvanced(tester);

    expect(find.text('Runtime details'), findsOneWidget);
    expect(find.text('Health endpoint'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('status failure is "service reachable, status unavailable"', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(
          health: true,
          statusError: const DiagnosticsApiException('status exploded'),
        ),
      ),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    expect(find.text('Runtime status temporarily unavailable'), findsOneWidget);
    expect(
      find.text(
        'The service is reachable, but runtime status is temporarily unavailable.',
      ),
      findsOneWidget,
    );
    expect(find.text('P2WLAN is running normally'), findsNothing);
    // With no status snapshot the service check reports the reachable fact
    // instead of claiming full health.
    expect(find.text('reachable'), findsOneWidget);
    expect(find.text('Running normally'), findsNothing);
    expect(find.textContaining('status exploded'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('stale snapshot keeps old checks and recommends refresh', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final clean = _mutateSnapshot(snapshot, _clearPeerErrors);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: clean),
        enableFreshnessTimer: true,
        maxSnapshotAge: const Duration(milliseconds: 300),
      ),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();
    await tester.pump(const Duration(milliseconds: 600));

    await tester.pumpWidget(
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    expect(find.text('Diagnostics data is stale'), findsOneWidget);
    expect(
      find.text('Showing data from the last successful refresh.'),
      findsOneWidget,
    );
    expect(find.text('Running normally'), findsOneWidget);
    expect(find.text('Try refreshing the status.'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('bad issues outrank staleness in the overview', (tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final reauth = _mutateSnapshot(snapshot, (raw) {
      raw['health']['reauth_required'] = true;
      return raw;
    });
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: reauth),
        enableFreshnessTimer: true,
        maxSnapshotAge: const Duration(milliseconds: 300),
      ),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();
    await tester.pump(const Duration(milliseconds: 600));

    await tester.pumpWidget(
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    // Stale data plus a real bad issue: attention wins, never the stale hero.
    expect(find.text('P2WLAN needs attention'), findsOneWidget);
    expect(find.text('Diagnostics data is stale'), findsNothing);
    expect(find.text('Re-authentication required'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('reauth shows actionable issue, never raw health reason', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final reauth = _mutateSnapshot(snapshot, (raw) {
      raw['health']['reauth_required'] = true;
      raw['health']['reason'] = 'control_auth_token_expired';
      return raw;
    });
    final stores = (await tester.runAsync(
      () =>
          _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: reauth)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    expect(find.text('Re-authentication required'), findsWidgets);
    expect(
      find.text('Your authentication has expired. Please sign in again.'),
      findsOneWidget,
    );
    expect(find.textContaining('control_auth_token_expired'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'critical task errors stay out of the default view and redacted',
    (tester) async {
      final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
      final failing = _mutateSnapshot(snapshot, (raw) {
        (raw['health']['critical_tasks'] as List<dynamic>)[0]['error'] =
            'SocketException: token=SUPER_SECRET';
        return raw;
      });
      final stores = (await tester.runAsync(
        () => _makeStores(
          api: _FakeDiagnosticsApi(health: true, snapshot: failing),
        ),
      ))!;
      addTearDown(stores.dispose);
      await stores.statusStore.refresh();

      await tester.pumpWidget(
        _TestApp(
          child: DiagnosticsPage(
            statusStore: stores.statusStore,
            permissionCheck: _noopPermissionCheck,
            logPreviewLoader: _noopLogPreviewLoader,
          ),
        ),
      );

      expect(
        find.text('Critical network tasks need attention'),
        findsOneWidget,
      );
      expect(
        find.text('A background network task is failing.'),
        findsOneWidget,
      );
      expect(find.textContaining('SocketException'), findsNothing);
      expect(find.textContaining('SUPER_SECRET'), findsNothing);

      await _expandAdvanced(tester);
      expect(find.text('Critical tasks'), findsOneWidget);
      expect(find.text('dataplane'), findsOneWidget);
      expect(find.textContaining('SUPER_SECRET'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('peer warnings are summarized, raw peer errors stay hidden', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final warn = _mutateSnapshot(snapshot, (raw) {
      final peers = raw['peers'] as List<dynamic>;
      (peers[0]['direct'] as Map<String, dynamic>)['last_error'] =
          'direct channel stale: endpoint unreachable';
      (peers[1]['direct'] as Map<String, dynamic>)['last_error'] = null;
      return raw;
    });
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: warn)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    expect(find.text('1 device needs path review'), findsOneWidget);
    expect(
      find.text('See the Devices page for specific devices.'),
      findsOneWidget,
    );
    expect(find.textContaining('endpoint unreachable'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('advanced content is lazily mounted', (tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    var permissionCalls = 0;
    var logCalls = 0;

    await tester.pumpWidget(
      _TestApp(
        child: DiagnosticsPage(
          statusStore: stores.statusStore,
          permissionCheck: () async {
            permissionCalls += 1;
            return _noopPreflight;
          },
          logPreviewLoader: () async {
            logCalls += 1;
            return const DiagnosticsLogPreview(
              path: '/tmp/p2wlan-daemon.log',
              content: 'info line',
              shownLineCount: 1,
            );
          },
        ),
      ),
    );

    expect(permissionCalls, 0);
    expect(logCalls, 0);
    expect(find.text('Platform permissions'), findsNothing);
    expect(find.text('Recent daemon logs'), findsNothing);

    await _expandAdvanced(tester);

    expect(permissionCalls, 1);
    expect(logCalls, 1);
    expect(find.text('Platform permissions'), findsOneWidget);
    expect(find.text('Recent daemon logs'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile capabilities hide local-only advanced panels', (
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
        child: DiagnosticsPage(
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('android'),
        ),
      ),
    );

    await _expandAdvanced(tester);

    expect(find.text('Runtime details'), findsOneWidget);
    expect(find.text('Protocol and MTU'), findsOneWidget);
    expect(find.text('Critical tasks'), findsOneWidget);
    expect(find.text('Raw /status JSON'), findsOneWidget);
    expect(find.text('Platform permissions'), findsNothing);
    expect(find.text('Create TUN'), findsNothing);
    expect(find.text('Modify routes'), findsNothing);
    expect(find.text('Recent daemon logs'), findsNothing);
    expect(find.text('Open logs'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('copy diagnostics summary is redacted', (tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final secret = _mutateSnapshot(snapshot, (raw) {
      raw['health']['reason'] =
          'authorization: Bearer SECRET; token=SUPER_SECRET';
      return raw;
    });
    final stores = (await tester.runAsync(
      () =>
          _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: secret)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    String? captured;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          captured =
              (call.arguments as Map<dynamic, dynamic>)['text'] as String?;
        }
        return null;
      },
    );
    addTearDown(() {
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        null,
      );
    });

    await tester.tap(find.text('Copy diagnostics summary'));
    await tester.pump();

    final text = captured ?? '';
    expect(text, contains('health_reason='));
    expect(text, isNot(contains('SUPER_SECRET')));
    expect(text, isNot(contains('SECRET')));
    expect(text, contains('<redacted>'));
    expect(tester.takeException(), isNull);
  });

  testWidgets('raw JSON view is redacted', (tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final secret = _mutateSnapshot(snapshot, (raw) {
      raw['token'] = 'SUPER_SECRET';
      raw['authorization'] = 'Bearer SECRET';
      return raw;
    });
    final stores = (await tester.runAsync(
      () =>
          _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: secret)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    await tester.pumpWidget(
      _TestApp(
        child: DiagnosticsPage(
          statusStore: stores.statusStore,
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );

    await _expandAdvanced(tester);
    tester
        .widget<OutlinedButton>(
          find.widgetWithText(OutlinedButton, 'Show JSON'),
        )
        .onPressed!();
    await tester.pump();

    expect(find.textContaining('SUPER_SECRET'), findsNothing);
    expect(find.textContaining('<redacted>'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('log preview is redacted before display and copy', (
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
        child: DiagnosticsPage(
          statusStore: stores.statusStore,
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: () async {
            return const DiagnosticsLogPreview(
              path: '/tmp/p2wlan-daemon.log',
              content: 'Authorization: Bearer SECRET\ntoken=SUPER_SECRET',
              shownLineCount: 2,
            );
          },
        ),
      ),
    );

    await _expandAdvanced(tester);

    expect(find.text('Recent daemon logs'), findsOneWidget);
    expect(find.textContaining('SUPER_SECRET'), findsNothing);
    expect(find.textContaining('<redacted>'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('open logs failure shows localized error, not raw exception', (
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
        child: DiagnosticsPage(
          statusStore: stores.statusStore,
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: () async {
            return const DiagnosticsLogPreview(
              path: '/tmp/p2wlan-daemon.log',
              content: 'info line',
              shownLineCount: 1,
            );
          },
          openLogs: () async {
            throw const ProcessException('open', [], 'mock failure', 1);
          },
        ),
      ),
    );

    await _expandAdvanced(tester);
    await tester.ensureVisible(find.text('Open logs'));
    await tester.pump();
    await tester.tap(find.text('Open logs'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));

    expect(find.textContaining('Could not open logs'), findsOneWidget);
    expect(
      find.textContaining('Make sure a file manager is available.'),
      findsOneWidget,
    );
    expect(find.textContaining('ProcessException'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  for (final size in const [Size(390, 844), Size(700, 1000), Size(1280, 900)]) {
    testWidgets(
      'diagnostics fits ${size.width.toInt()}x${size.height.toInt()}',
      (tester) async {
        final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
        final stores = (await tester.runAsync(
          () => _makeStores(
            api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
          ),
        ))!;
        addTearDown(stores.dispose);
        await stores.statusStore.refresh();

        await tester.binding.setSurfaceSize(size);
        addTearDown(() => tester.binding.setSurfaceSize(null));

        await tester.pumpWidget(
          _TestApp(
            child: DiagnosticsPage(
              statusStore: stores.statusStore,
              permissionCheck: _noopPermissionCheck,
              logPreviewLoader: _noopLogPreviewLoader,
            ),
          ),
        );
        expect(tester.takeException(), isNull);

        await _expandAdvanced(tester);
        expect(tester.takeException(), isNull);
      },
    );
  }
}

Future<void> _expandAdvanced(WidgetTester tester) async {
  final disclosure = find.byKey(const Key('diagnostics-advanced'));
  await tester.ensureVisible(disclosure);
  await tester.pumpAndSettle();
  await tester.tap(disclosure);
  await tester.pumpAndSettle();
}

DiagnosticsSnapshot _mutateSnapshot(
  DiagnosticsSnapshot snapshot,
  Map<String, dynamic> Function(Map<String, dynamic> raw) mutate,
) {
  final raw = jsonDecode(jsonEncode(snapshot.raw)) as Map<String, dynamic>;
  return DiagnosticsSnapshot.fromJson(mutate(raw));
}

/// A clean fixture has no peer path warnings (relay peers legitimately keep a
/// direct-probe failure note; that is expected and not a user issue).
Map<String, dynamic> _clearPeerErrors(Map<String, dynamic> raw) {
  for (final peer in raw['peers'] as List<dynamic>) {
    final direct =
        (peer as Map<String, dynamic>)['direct'] as Map<String, dynamic>;
    direct['last_error'] = null;
    direct['consecutive_failures'] = 0;
  }
  return raw;
}

Future<PermissionPreflight> _noopPermissionCheck() async => _noopPreflight;

Future<DiagnosticsLogPreview> _noopLogPreviewLoader() async {
  return const DiagnosticsLogPreview(
    path: '/tmp/p2wlan-daemon.log',
    content: '',
    shownLineCount: 0,
  );
}

const _noopPreflight = PermissionPreflight(
  platform: 'macOS',
  state: PermissionPreflightState.satisfied,
  canCreateTun: true,
  canModifyRoutes: true,
  elevationSupported: true,
  reasonCode: 'ready',
  message: 'permissions ok',
  checks: [],
);
