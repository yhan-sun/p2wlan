part of '../p15_widget_test.dart';

void _registerDashboardTests() {
  testWidgets(
    'Home manual command keeps selection and copy focus across reduced motion',
    (tester) async {
      tester.view.physicalSize = const Size(800, 1200);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(
        tester.platformDispatcher.clearAccessibilityFeaturesTestValue,
      );
      tester.platformDispatcher.accessibilityFeaturesTestValue =
          const FakeAccessibilityFeatures(disableAnimations: true);
      final api = _FakeDiagnosticsApi(health: false);
      final stores = (await tester.runAsync(
        () => _makeStores(api: api, daemonController: _ManualLaunchDaemon(api)),
      ))!;
      addTearDown(stores.dispose);
      await stores.statusStore.startDaemon();
      String? copied;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
            if (call.method == 'Clipboard.setData') {
              copied = (call.arguments as Map)['text'] as String;
            }
            return null;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(SystemChannels.platform, null),
      );
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
            capabilities: PlatformCapabilities.fromPlatform('linux'),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final toggle = find.byKey(const Key('home-manual-command-toggle'));
      final copy = find.byKey(const Key('home-manual-command-copy'));
      final command = find.byWidgetPredicate(
        (widget) =>
            widget is SelectableText &&
            widget.data == _ManualLaunchDaemon.command,
      );
      await tester.ensureVisible(toggle);
      await tester.pump();
      await tester.tap(toggle);
      await tester.pump();
      expect(command, findsOneWidget);
      expect(copy.hitTestable(), findsOneWidget);
      await tester.tap(toggle);
      await tester.pump();
      expect(command, findsNothing);
      expect(copy, findsNothing);
      expect(tester.takeException(), isNull);

      tester.platformDispatcher.accessibilityFeaturesTestValue =
          const FakeAccessibilityFeatures();
      await tester.pump();
      await tester.tap(toggle);
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 40));
      final editable = find.descendant(
        of: command,
        matching: find.byType(EditableText),
      );
      final editableState = tester.state(editable);
      final editor = tester.widget<EditableText>(editable);
      const selection = TextSelection(baseOffset: 0, extentOffset: 6);
      editor.focusNode.requestFocus();
      editor.controller.selection = selection;
      await tester.pump();
      tester.platformDispatcher.accessibilityFeaturesTestValue =
          const FakeAccessibilityFeatures(disableAnimations: true);
      await tester.pump();
      expect(tester.state(editable), same(editableState));
      expect(editor.focusNode.hasPrimaryFocus, isTrue);
      expect(editor.controller.selection, selection);
      final copyState = tester.state(copy);
      final copyFocus = Focus.of(
        tester.element(
          find
              .descendant(of: copy, matching: find.byType(GestureDetector))
              .first,
        ),
      );
      copyFocus.requestFocus();
      await tester.pump();
      for (final reduced in [false, true]) {
        tester.platformDispatcher.accessibilityFeaturesTestValue =
            FakeAccessibilityFeatures(disableAnimations: reduced);
        await tester.pump();
        expect(copyFocus.hasPrimaryFocus, isTrue);
        expect(tester.state(copy), same(copyState));
        expect(tester.state(editable), same(editableState));
        expect(editor.controller.selection, selection);
        expect(tester.takeException(), isNull);
      }
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(copied, _ManualLaunchDaemon.command);
      tester.platformDispatcher.accessibilityFeaturesTestValue =
          const FakeAccessibilityFeatures();
      await tester.pump();
      await tester.tap(toggle);
      await tester.pump();
      expect(command, findsNothing);
      expect(copy, findsNothing);
      tester.platformDispatcher.accessibilityFeaturesTestValue =
          const FakeAccessibilityFeatures(disableAnimations: true);
      await tester.pump();
      expect(command, findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  test('formats peer throughput in KB/s, MB/s, and GB/s', () {
    expect(formatTransferRate(null), '—');
    expect(formatTransferRate(1024), '1 KB/s');
    expect(formatTransferRate(1024 * 1024), '1 MB/s');
    expect(formatTransferRate(1024 * 1024 * 1024), '1 GB/s');
  });

  for (final probing in [false, true]) {
    testWidgets(
      'Home only warns for unconfirmed online paths (probing: $probing)',
      (tester) async {
        final base = (await tester.runAsync(_loadFixtureSnapshot))!;
        final peers = _fourPeerFixtures();
        final snapshot = _snapshotWithPeers(base, [
          peers[0],
          if (probing) peers[2],
          peers[3],
        ]);
        final stores = (await tester.runAsync(
          () => _makeStores(
            api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
          ),
        ))!;
        addTearDown(stores.dispose);
        await stores.statusStore.refresh();
        await tester.pumpWidget(
          _TestApp(
            child: DashboardPage(
              settingsStore: stores.settingsStore,
              statusStore: stores.statusStore,
            ),
          ),
        );
        final summary = tester.widget<Text>(
          find.byKey(const Key('home-connection-details-summary')),
        );
        expect(
          summary.data,
          probing ? 'Device connectivity: 1 / 2' : 'Control server · Normal',
        );
        await _expandHomeConnectionDetails(tester);
        expect(find.text(probing ? '1 / 2' : '1 / 1'), findsOneWidget);
        expect(tester.takeException(), isNull);
      },
    );
  }

  for (final outcome in ['success', 'changed address', 'disposed', 'failure']) {
    testWidgets(
      'Home copy feedback handles $outcome without stale confirmation',
      (tester) async {
        final base = (await tester.runAsync(_loadFixtureSnapshot))!;
        final api = _FakeDiagnosticsApi(health: true, snapshot: base);
        final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
        addTearDown(stores.dispose);
        final completion = Completer<Object?>();
        String? copied;
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(SystemChannels.platform, (call) async {
              if (call.method == 'Clipboard.setData') {
                copied = (call.arguments as Map)['text'] as String;
                return completion.future;
              }
              return null;
            });
        addTearDown(
          () => TestDefaultBinaryMessengerBinding
              .instance
              .defaultBinaryMessenger
              .setMockMethodCallHandler(SystemChannels.platform, null),
        );
        await stores.statusStore.refresh();
        await tester.pumpWidget(
          _TestApp(
            child: DashboardPage(
              settingsStore: stores.settingsStore,
              statusStore: stores.statusStore,
            ),
          ),
        );
        final copy = find.byKey(const Key('home-virtual-ip'));
        final confirmation = find.descendant(
          of: copy,
          matching: find.byIcon(Icons.check_rounded),
        );
        expect(tester.getSize(copy).height, greaterThanOrEqualTo(44));
        await tester.tap(copy);
        await tester.pump();
        expect(copied, base.virtualIp);
        expect(confirmation, findsNothing);
        if (outcome == 'changed address') {
          final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
          raw['virtual_ip'] = '10.20.0.50';
          api.snapshot = DiagnosticsSnapshot.fromJson(raw);
          await stores.statusStore.refresh();
          await tester.pump();
        } else if (outcome == 'disposed') {
          await tester.pumpWidget(const SizedBox.shrink());
        }
        if (outcome == 'failure') {
          completion.completeError(
            PlatformException(code: 'clipboard_unavailable'),
          );
        } else {
          completion.complete(null);
        }
        await tester.pumpAndSettle();
        if (outcome == 'success') {
          expect(confirmation, findsOneWidget);
          final semantics = tester.ensureSemantics();
          final node = tester.getSemantics(
            find.byKey(const Key('home-virtual-ip-feedback')),
          );
          expect(node.value, 'Copied');
          expect(node.label, contains('Copy virtual IP'));
          semantics.dispose();
          await tester.pump(const Duration(milliseconds: 1600));
          await tester.pumpAndSettle();
          expect(confirmation, findsNothing);
        } else {
          expect(confirmation, findsNothing);
          if (outcome == 'changed address') {
            expect(find.text('10.20.0.50'), findsOneWidget);
          }
          if (outcome == 'failure') {
            expect(find.text('Copy failed. Try again.'), findsOneWidget);
          }
        }
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }

  testWidgets('Home renders stopped state with start action', (tester) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Bring your devices together'), findsOneWidget);
    expect(
      find.text(
        'Start the local network service to bring this device onto your virtual network.',
      ),
      findsOneWidget,
    );
    expect(find.text('Not running'), findsOneWidget);
    expect(find.text('Check issues'), findsNothing);
    expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);
    // No snapshot: no data regions at all.
    expect(find.text('Online devices'), findsNothing);
    expect(find.text('Network components'), findsNothing);
  });

  testWidgets('macOS start does not show a repeated authorization explainer', (
    tester,
  ) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
    try {
      final stores = (await tester.runAsync(
        () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
      ))!;
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );

      await tester.tap(find.byKey(const Key('dashboard-start-button')));
      await tester.pumpAndSettle();

      expect(find.text('macOS administrator access required'), findsNothing);
      expect(find.text('Continue'), findsNothing);
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
  });

  testWidgets(
    'Home keeps initial and periodic status detection in the background',
    (tester) async {
      final api = _ControllableOfflineDiagnosticsApi();
      final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
      addTearDown(stores.dispose);

      final initialHealth = api.pauseNextHealth();
      final initialRefresh = stores.statusStore.refresh(silent: true);
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );

      // Detection starts immediately, but it is background state: Home keeps
      // its stable default and never presents a foreground loading task.
      expect(stores.statusStore.refreshing, isTrue);
      expect(stores.statusStore.refreshActivityVisible, isFalse);
      expect(find.text('Fetching network status…'), findsNothing);
      expect(find.text('Bring your devices together'), findsOneWidget);
      expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsNothing);
      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNull,
      );

      initialHealth.complete(false);
      await initialRefresh;
      await tester.pump();
      expect(find.text('Bring your devices together'), findsOneWidget);
      expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNotNull,
      );

      // A periodic poll must not send the confirmed stopped UI back to the
      // loading state while its health request is in flight.
      final nextHealth = api.pauseNextHealth();
      final periodicRefresh = stores.statusStore.refresh(silent: true);
      await tester.pump();
      expect(stores.statusStore.refreshing, isTrue);
      expect(stores.statusStore.refreshActivityVisible, isFalse);
      expect(find.text('Fetching network status…'), findsNothing);
      expect(find.text('Bring your devices together'), findsOneWidget);
      expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
      expect(find.text('Refreshing...'), findsNothing);
      expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);
      expect(find.byKey(const Key('dashboard-check-button')), findsNothing);
      expect(find.byType(CircularProgressIndicator), findsNothing);
      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNotNull,
      );

      nextHealth.complete(false);
      await periodicRefresh;
      await tester.pump();
      expect(find.text('Bring your devices together'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('Home shows healthy network from a real fixture snapshot', (
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
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // Healthy hero: status + Virtual IP first, with no redundant identity
    // sentence or network-id line.
    expect(find.text('Local network connected'), findsOneWidget);
    expect(find.text('Network status'), findsNothing);
    expect(find.text('Normal'), findsNothing);
    expect(find.text('Connection details'), findsOneWidget);
    expect(find.text('Control server'), findsNothing);
    expect(find.text('Your device is on the P2WLAN network'), findsNothing);
    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('Virtual IP address'), findsOneWidget);
    expect(find.textContaining('Network ID'), findsNothing);

    // Key metrics from peer state plus the local NAT profile.
    expect(_heroCount(tester, 'dashboard-count-online'), '2');
    expect(_heroCount(tester, 'dashboard-count-direct'), '1');
    expect(_heroCount(tester, 'dashboard-count-relay'), '1');

    // Device preview section is titled "Devices" and contains connected peers.
    expect(find.text('Devices'), findsOneWidget);
    expect(find.text('Online devices'), findsWidgets);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('10.20.0.11'), findsOneWidget);
    expect(find.text('offline-printer'), findsNothing);

    // Healthy hero: no duplicate inline refresh; status polling is automatic.
    expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);

    final requestsBeforeDetails =
        (stores.statusStore.diagnosticsApi as _FakeDiagnosticsApi)
            .statusFetchCount;
    await _expandHomeConnectionDetails(tester);
    expect(
      (stores.statusStore.diagnosticsApi as _FakeDiagnosticsApi)
          .statusFetchCount,
      requestsBeforeDetails,
    );
    expect(_heroCount(tester, 'dashboard-nat-type'), 'Restricted Cone');

    // Network components: only rows the fixture can judge. The fixture has no
    // ready_phase, so the Overlay route row is honestly omitted.
    expect(find.text('Control server'), findsOneWidget);
    expect(find.text('Device connectivity'), findsOneWidget);
    expect(find.text('2 / 2'), findsOneWidget);
    expect(find.text('Overlay route'), findsNothing);

    // Healthy → no issue CTA.
    expect(find.text('Check issues'), findsNothing);
  });

  testWidgets(
    'Home shows a conservative NAT subtype when filtering is unavailable',
    (tester) async {
      final base = (await tester.runAsync(_loadFixtureSnapshot))!;
      final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
      raw['nat_profile'] = {
        'mapping_behavior': 'endpoint_independent',
        'filtering_behavior': 'unknown',
        'public_endpoint': '198.51.100.20:62000',
        'confidence': 90,
      };
      final snapshot = DiagnosticsSnapshot.fromJson(raw);
      final stores = (await tester.runAsync(
        () => _makeStores(
          api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
        ),
      ))!;
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );

      await _expandHomeConnectionDetails(tester);
      expect(_heroCount(tester, 'dashboard-nat-type'), 'Port-Restricted Cone');
      expect(find.text('Endpoint independent'), findsNothing);
    },
  );

  testWidgets('Home distinguishes API reachability from online lease health', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
    final health = raw['health'] as Map<String, dynamic>;
    health
      ..['status'] = 'degraded'
      ..['control_connected'] = false
      ..['control_api_reachable'] = true
      ..['device_lease_healthy'] = false
      ..['last_device_lease_success_secs_ago'] = 12;
    raw['ready_phase'] = 'connecting_control';
    final snapshot = DiagnosticsSnapshot.fromJson(raw);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Degraded'), findsOneWidget);
    expect(find.text('Online lease refresh failed'), findsOneWidget);
    expect(
      find.text(
        "This device's server-side online lease could not be refreshed; peers may now see it as offline.",
      ),
      findsOneWidget,
    );
    expect(find.text('Control server'), findsOneWidget);
  });

  for (final component in ['control', 'route']) {
    testWidgets(
      'Home folded details expose a new $component issue without reopening',
      (tester) async {
        final base = (await tester.runAsync(_loadFixtureSnapshot))!;
        final api = _FakeDiagnosticsApi(health: true, snapshot: base);
        final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
        addTearDown(stores.dispose);
        await stores.statusStore.refresh();
        await tester.pumpWidget(
          _TestApp(
            child: DashboardPage(
              settingsStore: stores.settingsStore,
              statusStore: stores.statusStore,
            ),
          ),
        );
        await _expandHomeConnectionDetails(tester);
        await tester.tap(find.text('Connection details'));
        await tester.pumpAndSettle();
        expect(find.text('Control server'), findsNothing);
        final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
        final health = raw['health'] as Map<String, dynamic>;
        health['status'] = 'degraded';
        if (component == 'control') {
          health['control_connected'] = false;
          health['control_api_reachable'] = false;
        } else {
          raw['ready_phase'] = 'error';
        }
        api.snapshot = DiagnosticsSnapshot.fromJson(raw);
        await stores.statusStore.refresh();
        await tester.pumpAndSettle();
        final summary = tester.widget<Text>(
          find.byKey(const Key('home-connection-details-summary')),
        );
        expect(
          summary.data,
          contains(
            component == 'control'
                ? 'Control server: Disconnected'
                : 'Overlay route: Error',
          ),
        );
        expect(summary.data, isNot(contains('Normal')));
        // Updating the summary does not override the user's closed disclosure.
        expect(find.text('Control server'), findsNothing);
        expect(find.text('Overlay route'), findsNothing);
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets('Home never counts an offline peer with a stale active path', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stale = _peerJson(
      nodeId: 'offline-stale-direct',
      deviceName: 'offline-stale-direct',
      virtualIp: '10.20.0.99',
      online: false,
      state: 'direct',
      activePath: 'direct',
      relayConfirmedEndpoint: null,
      direct: {'latency_ms': 1},
      relay: _emptyPathHealth(),
    );
    final snapshot = _snapshotWithPeers(base, [stale]);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(_heroCount(tester, 'dashboard-count-online'), '0');
    expect(_heroCount(tester, 'dashboard-count-direct'), '0');
    expect(_heroCount(tester, 'dashboard-count-relay'), '0');
    expect(find.text('offline-stale-direct'), findsNothing);
  });

  testWidgets(
    'Home does not confirm a selected path before validation commits',
    (tester) async {
      final base = (await tester.runAsync(_loadFixtureSnapshot))!;
      final selected =
          _peerJson(
              nodeId: 'selected-before-validation',
              deviceName: 'Selected device',
              virtualIp: '10.20.0.98',
              online: true,
              state: 'idle',
              activePath: null,
              relayConfirmedEndpoint: null,
              direct: _emptyPathHealth(),
              relay: _emptyPathHealth(),
            )
            ..['current_path_selection'] = {
              'path': 'direct',
              'direct_confirmed': true,
            };
      final snapshot = _snapshotWithPeers(base, [selected]);
      // Selection can arrive before the daemon commits verified active state.
      expect(snapshot.peers.single.path, 'direct');
      expect(snapshot.peers.single.isDirectVerified, isFalse);
      final stores = (await tester.runAsync(
        () => _makeStores(
          api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
        ),
      ))!;
      addTearDown(stores.dispose);
      await stores.statusStore.refresh();
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );
      expect(_heroCount(tester, 'dashboard-count-online'), '1');
      expect(_heroCount(tester, 'dashboard-count-available'), '0');
      expect(_heroCount(tester, 'dashboard-count-direct'), '0');
      final row = find.byKey(
        const Key('home-device-row-selected-before-validation'),
      );
      expect(
        find.descendant(of: row, matching: find.text('probing')),
        findsOneWidget,
      );
    },
  );

  testWidgets('Home counts an online peer without a verified path as probing', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final pending = _peerJson(
      nodeId: 'online-no-path',
      deviceName: 'online-no-path',
      virtualIp: '10.20.0.98',
      online: true,
      state: 'idle',
      activePath: null,
      relayConfirmedEndpoint: null,
      direct: _emptyPathHealth(),
      relay: _emptyPathHealth(),
    );
    final snapshot = _snapshotWithPeers(base, [pending]);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(_heroCount(tester, 'dashboard-count-online'), '1');
    expect(_heroCount(tester, 'dashboard-count-direct'), '0');
    expect(_heroCount(tester, 'dashboard-count-relay'), '0');
    expect(find.text('online-no-path'), findsOneWidget);
    expect(find.text('probing'), findsOneWidget);
  });

  testWidgets('Home keeps technical noise off the default page', (
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
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    for (final technical in [
      'UDP',
      'Request duration',
      'Last refresh',
      'Snapshot',
      'Endpoint state',
      'Peer ID',
      'MTU',
      'NAT probabilities',
    ]) {
      expect(
        find.text(technical),
        findsNothing,
        reason: 'technical field "$technical" must not appear on Home',
      );
    }
  });

  testWidgets('Home shows last-known data with a stale note', (tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
        enableFreshnessTimer: true,
        maxSnapshotAge: const Duration(milliseconds: 50),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );
    await tester.pump(const Duration(milliseconds: 120));

    // Last-known data and its stale note remain while polling retries in the
    // background; Home does not expose a competing manual refresh task.
    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('Data may be out of date'), findsOneWidget);
    expect(find.byKey(const Key('home-stale-refresh')), findsNothing);
    expect(find.text('Last known connection'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-count-available')), findsNothing);
    expect(find.text('Network components'), findsNothing);
    // Staleness is not an issue banner.
    expect(find.text('Check issues'), findsNothing);
  });

  testWidgets('Home separates status endpoint errors from health', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(
          health: true,
          statusError: const DiagnosticsApiException('status fixture failed'),
        ),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // Health is up but no snapshot: unavailable, never stopped.
    expect(find.text('Runtime status temporarily unavailable'), findsOneWidget);
    expect(
      find.text(
        'The service is reachable, but runtime status is temporarily unavailable.',
      ),
      findsOneWidget,
    );
    expect(find.text('Cannot reach P2WLAN'), findsNothing);
    expect(
      find.text('The local network service is currently unavailable.'),
      findsNothing,
    );
    expect(find.text('Not running'), findsNothing);
    expect(find.text('Status unavailable'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-check-button')), findsNothing);
    expect(find.text('Online devices'), findsNothing);
  });

  for (final languageCode in ['en', 'zh-CN']) {
    testWidgets(
      'Home keeps reachable local 401 distinct from stopped ($languageCode)',
      (tester) async {
        final strings = AppStrings.fromCode(languageCode);
        final stores = (await tester.runAsync(
          () => _makeStores(
            api: _FakeDiagnosticsApi(
              health: true,
              statusError: const DiagnosticsApiException(
                'GET /status returned HTTP 401',
                statusCode: 401,
              ),
            ),
          ),
        ))!;
        addTearDown(stores.dispose);

        await stores.statusStore.refresh();
        expect(stores.statusStore.healthReachable, isTrue);
        expect(stores.statusStore.snapshot, isNull);
        expect(
          stores.statusStore.lastStatusError,
          'local_diagnostics_auth_failed',
        );
        await tester.pumpWidget(
          _TestApp(
            strings: strings,
            child: DashboardPage(
              settingsStore: stores.settingsStore,
              statusStore: stores.statusStore,
              capabilities: PlatformCapabilities.fromPlatform('macos'),
            ),
          ),
        );

        expect(find.text(strings.issueStatusUnavailableTitle), findsOneWidget);
        expect(find.text(strings.issueStatusUnavailableDetail), findsOneWidget);
        expect(
          find.text(strings.isZh ? '状态不可读' : 'Status unavailable'),
          findsOneWidget,
        );
        expect(
          find.text(strings.statusMessage('local_diagnostics_auth_failed')!),
          findsOneWidget,
        );
        expect(find.text(strings.homeUnavailableTitle), findsNothing);
        expect(find.text(strings.homeUnavailableDetail), findsNothing);
        expect(find.text(strings.notRunning), findsNothing);
        expect(find.text(strings.statusNormal), findsNothing);
        expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
        expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets('Home shows device path and latency in a compact preview', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _fourPeerFixtures());
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('probing-phone'), findsOneWidget);
    expect(
      tester.getTopLeft(find.text('10.20.0.11')).dy,
      greaterThan(tester.getTopLeft(find.text('direct-laptop')).dy),
    );
    expect(find.text('offline-printer'), findsNothing);
    // Metric labels add one more occurrence each.
    expect(find.text('Direct'), findsNWidgets(2));
    expect(find.text('Relay'), findsNWidgets(2));
    expect(find.text('probing'), findsOneWidget);
    expect(find.text('Offline'), findsNothing);
    // Useful connection facts stay on the cover; deeper metadata belongs in
    // the opened detail surface.
    expect(find.text('12 ms'), findsOneWidget);
    expect(find.text('43 ms'), findsOneWidget);
    expect(find.text('probe RTT 8 ms'), findsNothing);
    expect(find.text('8 ms'), findsNothing);
  });

  testWidgets(
    'Home keeps online order and moves a reconnected peer to the end',
    (tester) async {
      final base = (await tester.runAsync(_loadFixtureSnapshot))!;
      final initial = _snapshotWithPeers(base, _fourPeerFixtures());
      final api = _FakeDiagnosticsApi(health: true, snapshot: initial);
      final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );

      double rowTop(String nodeId) =>
          tester.getTopLeft(find.byKey(Key('home-device-row-$nodeId'))).dy;

      expect(rowTop('node-direct'), lessThan(rowTop('node-relay')));
      expect(rowTop('node-relay'), lessThan(rowTop('node-probing')));

      final offlinePeers = _fourPeerFixtures();
      final directOffline = offlinePeers.firstWhere(
        (peer) => peer['node_id'] == 'node-direct',
      );
      directOffline
        ..['online'] = false
        ..['state'] = 'unknown'
        ..['active_path'] = null
        ..['current_path_selection'] = null;
      api.snapshot = _snapshotWithPeers(base, offlinePeers);
      await stores.statusStore.refresh();
      await tester.pump();

      final restoredPeers = _fourPeerFixtures();
      api.snapshot = _snapshotWithPeers(base, restoredPeers);
      await stores.statusStore.refresh();
      await tester.pump();

      expect(rowTop('node-relay'), lessThan(rowTop('node-probing')));
      expect(rowTop('node-probing'), lessThan(rowTop('node-direct')));
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('Device rows order speed, latency, then connection path', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final initialPeers = _fourPeerFixtures();
    final initialSnapshot = _snapshotWithPeers(base, initialPeers);
    final updatedPeers = _fourPeerFixtures();
    final direct = updatedPeers.firstWhere(
      (peer) => peer['node_id'] == 'node-direct',
    );
    direct['bytes_sent'] = 1024 * 1024;
    final updatedSnapshot = _snapshotWithPeers(base, updatedPeers);
    final api = _FakeDiagnosticsApi(health: true, snapshot: initialSnapshot);
    final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    api.snapshot = updatedSnapshot;
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(milliseconds: 20)),
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    final row = find.byKey(const Key('home-device-row-node-direct'));
    final labels = tester
        .widgetList<Text>(find.descendant(of: row, matching: find.byType(Text)))
        .map((text) => text.data)
        .whereType<String>()
        .toList();
    final speedIndex = labels.indexWhere(
      (label) =>
          label.contains('KB/s') ||
          label.contains('MB/s') ||
          label.contains('GB/s'),
    );
    final latencyIndex = labels.indexOf('12 ms');
    final pathIndex = labels.indexOf('Direct');
    expect(speedIndex, greaterThanOrEqualTo(0));
    expect(latencyIndex, greaterThan(speedIndex));
    expect(pathIndex, greaterThan(latencyIndex));
  });

  testWidgets('Home shows exact hero connection counts', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _fourPeerFixtures());
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // 1 direct + 1 relay + 1 probing = 3 online; offline never counts.
    // Probing is deliberately not a fourth metric.
    expect(_heroCount(tester, 'dashboard-count-online'), '3');
    expect(_heroCount(tester, 'dashboard-count-direct'), '1');
    expect(_heroCount(tester, 'dashboard-count-relay'), '1');
    expect(find.byKey(const Key('dashboard-count-probing')), findsNothing);
  });

  testWidgets('Home previews at most five devices', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _peerFixturesForCount(6));
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // Attention first, then relay and direct. Offline peers are excluded from
    // the Home preview before the five-device cap is applied.
    expect(find.text('probing-phone'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('relay-server2'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('direct-desktop'), findsOneWidget);
    expect(find.text('offline-printer'), findsNothing);
  });

  testWidgets('Home handles a healthy network with no peers', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeerCount(base, 0);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('No other devices online'), findsOneWidget);
    expect(
      find.text('Invite another device to the same room to see it here.'),
      findsOneWidget,
    );
    await _expandHomeConnectionDetails(tester);
    expect(find.text('0 / 0'), findsOneWidget);
    expect(_heroCount(tester, 'dashboard-count-online'), '0');
  });

  testWidgets('Home shows an issue banner with troubleshooting CTA', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
    (raw['health'] as Map<String, dynamic>)['status'] = 'degraded';
    (raw['health'] as Map<String, dynamic>)['reason'] =
        'Overlay route or connection state needs review';
    final snapshot = DiagnosticsSnapshot.fromJson(raw);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    var opened = false;
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          onOpenTroubleshooting: () => opened = true,
        ),
      ),
    );

    expect(find.text('Network issue found'), findsOneWidget);
    expect(
      find.text('Overlay route or connection state needs review'),
      findsOneWidget,
    );
    expect(find.text('Check issues'), findsOneWidget);
    expect(find.text('Degraded'), findsOneWidget);

    await tester.tap(find.byKey(const Key('home-check-issues')));
    expect(opened, isTrue);
  });

  testWidgets('Shell: View all devices opens the Devices section', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

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
        child: P2WlanShell(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(DashboardPage), findsOneWidget);
    expect(find.byType(DesktopSidebar), findsOneWidget);

    await tester.tap(find.byKey(const Key('home-device-row-peer-direct-001')));
    await tester.pumpAndSettle();
    // Home hands the selected peer to the real Devices page. The list owns
    // the detail surface, so actions such as speed test are identical from
    // either entry point.
    expect(find.byType(NodesPage), findsOneWidget);
    expect(find.byType(Dialog), findsOneWidget);
    expect(
      find.byKey(const Key('node-detail-speedtest-peer-direct-001')),
      findsOneWidget,
    );
    expect(find.text('24 ms'), findsWidgets);
    await tester.tap(find.byKey(const Key('nodes-detail-close')));
    await tester.pumpAndSettle();

    // A detail opened from Home returns to Home after it is dismissed.
    expect(find.byType(DashboardPage), findsOneWidget);
    expect(find.byType(NodesPage), findsNothing);
    await tester.tap(find.byKey(const Key('home-view-all-devices')));
    await tester.pumpAndSettle();

    expect(find.byType(NodesPage), findsOneWidget);
    expect(find.byType(DashboardPage), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Shell: issue CTA opens Troubleshooting on mobile', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
    (raw['health'] as Map<String, dynamic>)['status'] = 'degraded';
    (raw['health'] as Map<String, dynamic>)['reason'] =
        'Overlay route or connection state needs review';
    final snapshot = DiagnosticsSnapshot.fromJson(raw);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: P2WlanShell(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Check issues'), findsOneWidget);
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(4),
    );

    await tester.tap(find.byKey(const Key('home-check-issues')));
    await tester.pumpAndSettle();

    expect(find.byType(DiagnosticsPage), findsOneWidget);
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(4),
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('Home keeps actions usable on narrow screens', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

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
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('10.20.0.10'), findsOneWidget);
    final stopButton = find.byKey(const Key('dashboard-stop-button'));
    expect(stopButton, findsOneWidget);
    expect(
      find.descendant(of: stopButton, matching: find.text('Stop P2WLAN')),
      findsOneWidget,
    );
    // The destructive action follows the Virtual IP value, not the network
    // status header, and remains a discoverable full-label button on phones.
    expect(
      tester.getCenter(stopButton).dy,
      greaterThan(tester.getBottomRight(find.text('Virtual IP address')).dy),
    );
    // Healthy: status polling is automatic; the hero does not add a refresh.
    expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Home uses remote-management state on mobile capabilities', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    const mobileCapabilities = PlatformCapabilities(
      canControlLocalDaemon: false,
      canRequestElevation: false,
      canVerifyRoutes: false,
      canRepairRoutes: false,
      canOpenLocalLogs: false,
      canCreateSupportBundle: false,
      canUseSystemTray: false,
      canActAsLocalVpnNode: false,
      canManageRemoteDevices: true,
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: mobileCapabilities,
          onOpenDevices: () {},
        ),
      ),
    );

    expect(find.text('Mobile management mode'), findsOneWidget);
    expect(
      find.textContaining('does not start the desktop daemon'),
      findsOneWidget,
    );
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
    expect(find.byKey(const Key('mobile-home-open-devices')), findsOneWidget);
  });

  testWidgets('Home with no local daemon control never offers Start', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
    ))!;
    addTearDown(stores.dispose);

    const mobileCapabilities = PlatformCapabilities(
      canControlLocalDaemon: false,
      canRequestElevation: false,
      canVerifyRoutes: false,
      canRepairRoutes: false,
      canOpenLocalLogs: false,
      canCreateSupportBundle: false,
      canUseSystemTray: false,
      canActAsLocalVpnNode: false,
      canManageRemoteDevices: true,
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: mobileCapabilities,
        ),
      ),
    );

    expect(find.text('Mobile management mode'), findsOneWidget);
    expect(find.text('Cannot reach P2WLAN'), findsNothing);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.text('Start P2WLAN'), findsNothing);
    expect(find.byKey(const Key('dashboard-check-button')), findsNothing);
  });

  testWidgets('Home adapts layout across breakpoints', (tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    const sizes = [Size(390, 844), Size(700, 1000), Size(1280, 900)];
    for (final size in sizes) {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );
      await tester.pump();

      expect(tester.takeException(), isNull, reason: 'size $size');
      expect(find.text('10.20.0.10'), findsOneWidget, reason: 'size $size');
      expect(find.text('direct-laptop'), findsOneWidget, reason: 'size $size');
      await _expandHomeConnectionDetails(tester);
      expect(find.text('Control server'), findsOneWidget, reason: 'size $size');
      expect(
        find.text('Connection details'),
        findsOneWidget,
        reason: 'size $size',
      );
    }
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });

  for (final width in [390.0, 800.0]) {
    testWidgets(
      'Home preview keeps long identities readable at $width and 200% text',
      (tester) async {
        tester.view.physicalSize = Size(width, 1100);
        tester.view.devicePixelRatio = 1;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        final base = (await tester.runAsync(_loadFixtureSnapshot))!;
        final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
        final first =
            (raw['peers'] as List<dynamic>).first as Map<String, dynamic>;
        first['device_name'] = 'Engineering workstation';
        final snapshot = DiagnosticsSnapshot.fromJson(raw);
        final stores = (await tester.runAsync(
          () => _makeStores(
            api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
          ),
        ))!;
        addTearDown(stores.dispose);
        await stores.statusStore.refresh();
        PeerSnapshot? opened;
        await tester.pumpWidget(
          MaterialApp(
            theme: AppTheme.lightTheme,
            home: AppStringsScope(
              strings: AppStrings.fromCode('en'),
              child: MediaQuery(
                data: MediaQueryData(
                  size: Size(width, 1100),
                  textScaler: const TextScaler.linear(2),
                ),
                child: Scaffold(
                  body: Row(
                    children: [
                      if (width >= 800) const SizedBox(width: 197),
                      Expanded(
                        child: DashboardPage(
                          settingsStore: stores.settingsStore,
                          statusStore: stores.statusStore,
                          onOpenPeer: (peer) => opened = peer,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        );
        await tester.pump();
        expect(tester.takeException(), isNull);
        final row = find.byKey(
          Key('home-device-row-${snapshot.peers.first.nodeId}'),
        );
        await tester.ensureVisible(row);
        await tester.pump();
        final name = find.descendant(
          of: row,
          matching: find.text('Engineering workstation'),
        );
        expect(tester.widget<Text>(name).maxLines, isNull);
        expect(
          find.descendant(of: row, matching: find.text('10.20.0.11')),
          findsOneWidget,
        );
        await tester.tap(row);
        expect(opened?.nodeId, snapshot.peers.first.nodeId);
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets('Home dark theme renders the full healthy page', (tester) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _DesignSystemHost(
        dark: true,
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    await _expandHomeConnectionDetails(tester);
    expect(find.text('Control server'), findsOneWidget);
    expect(find.text('Connection details'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

Map<String, dynamic> _peerJson({
  required String nodeId,
  required String deviceName,
  required String virtualIp,
  required bool online,
  required String state,
  String? activePath,
  required String? relayConfirmedEndpoint,
  int? relayConfirmedGeneration,
  int? remoteRelayLatencyMs,
  required Map<String, dynamic> direct,
  required Map<String, dynamic> relay,
  Map<String, dynamic>? currentPathSelection,
}) {
  return {
    'node_id': nodeId,
    'device_name': deviceName,
    'app_version': '1.0.0',
    'virtual_ip': virtualIp,
    'endpoint': null,
    'nat_type': 'unknown',
    'online': online,
    'last_seen': 0,
    'remote_relay_latency_ms': remoteRelayLatencyMs,
    'state': state,
    'active_path': activePath,
    'direct_type': 'unknown',
    'is_relay': false,
    'bytes_sent': 0,
    'bytes_received': 0,
    'relay_server': null,
    'warning': null,
    'connected_for_ms': null,
    'direct': direct,
    'relay': relay,
    'current_path_selection': currentPathSelection,
    'relay_confirmed_endpoint': relayConfirmedEndpoint,
    'relay_confirmed_generation': relayConfirmedGeneration,
  };
}

Map<String, dynamic> _emptyPathHealth() => {
  'last_success_age_ms': null,
  'last_failure_age_ms': null,
  'consecutive_failures': 0,
  'last_error': null,
  'last_error_code': null,
  'latency_ms': null,
  'rtt_ewma_ms': null,
};

/// Four peers matching the real model rules: a verified direct peer, a
/// verified relay peer (matching encrypted relay ACK), a direct trial still
/// probing (candidate RTT only), and an offline peer.
List<Map<String, dynamic>> _fourPeerFixtures() {
  final directPeer = _peerJson(
    nodeId: 'node-direct',
    deviceName: 'direct-laptop',
    virtualIp: '10.20.0.11',
    online: true,
    state: 'direct',
    activePath: 'direct',
    relayConfirmedEndpoint: null,
    direct: {
      'last_success_age_ms': 100,
      'last_failure_age_ms': null,
      'consecutive_failures': 0,
      'last_error': null,
      'last_error_code': null,
      'latency_ms': 12,
      'rtt_ewma_ms': null,
    },
    relay: _emptyPathHealth(),
    currentPathSelection: {
      'path': 'direct',
      'direct_endpoint': '198.51.100.21:61111',
      'reason_code': 'path_direct_confirmed',
      'reason': 'public UDP pair confirmed',
      'direct_confirmed': true,
      'relay_hedged': false,
    },
  );
  final relayPeer = _peerJson(
    nodeId: 'node-relay',
    deviceName: 'relay-nas',
    virtualIp: '10.20.0.12',
    online: true,
    state: 'relay',
    activePath: 'relay',
    relayConfirmedEndpoint: '203.0.113.10:18081',
    relayConfirmedGeneration: 5,
    remoteRelayLatencyMs: 91,
    direct: _emptyPathHealth(),
    relay: {
      'last_success_age_ms': 300,
      'last_failure_age_ms': null,
      'consecutive_failures': 0,
      'last_error': null,
      'last_error_code': null,
      // Only this daemon's timed peer RTT is displayable. The remote daemon's
      // peer-to-relay RTT above intentionally differs and must be ignored.
      'latency_ms': 43,
      'rtt_ewma_ms': null,
    },
    currentPathSelection: {
      'path': 'relay',
      'direct_endpoint': null,
      'reason_code': 'path_relay_fallback',
      'reason': 'direct path unavailable; relay confirmed',
      'direct_confirmed': false,
      'relay_hedged': false,
    },
  );
  final probingPeer = _peerJson(
    nodeId: 'node-probing',
    deviceName: 'probing-phone',
    virtualIp: '10.20.0.13',
    online: true,
    state: 'connecting',
    activePath: null,
    relayConfirmedEndpoint: null,
    direct: {
      'last_success_age_ms': null,
      'last_failure_age_ms': null,
      'consecutive_failures': 0,
      'last_error': null,
      'last_error_code': null,
      'latency_ms': 8,
      'rtt_ewma_ms': null,
    },
    relay: _emptyPathHealth(),
    currentPathSelection: {
      'path': 'direct',
      'direct_endpoint': '198.51.100.22:61112',
      'reason_code': 'path_direct_trial',
      'reason': 'candidate probe succeeded',
      'direct_confirmed': false,
      'relay_hedged': false,
    },
  );
  final offlinePeer = _peerJson(
    nodeId: 'node-offline',
    deviceName: 'offline-printer',
    virtualIp: '10.20.0.14',
    online: false,
    state: 'unknown',
    activePath: null,
    relayConfirmedEndpoint: null,
    direct: _emptyPathHealth(),
    relay: _emptyPathHealth(),
  );
  return [directPeer, relayPeer, probingPeer, offlinePeer];
}

/// Five peers (4 fixtures + one extra verified direct peer).
List<Map<String, dynamic>> _fivePeerFixtures() {
  return [
    ..._fourPeerFixtures(),
    _peerJson(
      nodeId: 'node-direct2',
      deviceName: 'direct-desktop',
      virtualIp: '10.20.0.15',
      online: true,
      state: 'direct',
      activePath: 'direct',
      relayConfirmedEndpoint: null,
      direct: {
        'last_success_age_ms': 60,
        'last_failure_age_ms': null,
        'consecutive_failures': 0,
        'last_error': null,
        'last_error_code': null,
        'latency_ms': 18,
        'rtt_ewma_ms': null,
      },
      relay: _emptyPathHealth(),
      currentPathSelection: {
        'path': 'direct',
        'direct_endpoint': '198.51.100.23:61113',
        'reason_code': 'path_direct_confirmed',
        'reason': 'public UDP pair confirmed',
        'direct_confirmed': true,
        'relay_hedged': false,
      },
    ),
  ];
}

/// A pool of distinct peers used to build snapshots with any 1..6 peer count.
/// First four come from [_fourPeerFixtures]; the rest are distinct verified
/// paths (direct / relay) matching the real model rules.
List<Map<String, dynamic>> _peerFixturesForCount(int count) {
  assert(count >= 1 && count <= 6);
  final pool = <Map<String, dynamic>>[
    ..._fourPeerFixtures(),
    ..._fivePeerFixtures().skip(4),
    _peerJson(
      nodeId: 'node-relay2',
      deviceName: 'relay-server2',
      virtualIp: '10.20.0.16',
      online: true,
      state: 'relay',
      activePath: 'relay',
      relayConfirmedEndpoint: '203.0.113.11:18082',
      relayConfirmedGeneration: 7,
      direct: _emptyPathHealth(),
      relay: {
        'last_success_age_ms': 250,
        'last_failure_age_ms': null,
        'consecutive_failures': 0,
        'last_error': null,
        'last_error_code': null,
        'latency_ms': 55,
        'rtt_ewma_ms': null,
      },
      currentPathSelection: {
        'path': 'relay',
        'direct_endpoint': null,
        'reason_code': 'path_relay_fallback',
        'reason': 'direct path unavailable; relay confirmed',
        'direct_confirmed': false,
        'relay_hedged': false,
      },
    ),
  ];
  return pool.take(count).toList();
}

String _heroCount(WidgetTester tester, String key) {
  final text = tester.widget<Text>(
    find
        .descendant(of: find.byKey(Key(key)), matching: find.byType(Text))
        .first,
  );
  return text.data!;
}

DiagnosticsSnapshot _snapshotWithPeers(
  DiagnosticsSnapshot base,
  List<Map<String, dynamic>> peers,
) {
  final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
  raw['peers'] = peers;
  (raw['stats'] as Map<String, dynamic>)['total_peers'] = peers.length;
  raw['virtual_ip'] = '10.20.0.5';
  return DiagnosticsSnapshot.fromJson(raw);
}

class _ControllableOfflineDiagnosticsApi extends _FakeDiagnosticsApi {
  _ControllableOfflineDiagnosticsApi() : super(health: false);

  Completer<bool>? _nextHealth;

  Completer<bool> pauseNextHealth() {
    assert(_nextHealth == null, 'A health probe is already paused.');
    return _nextHealth = Completer<bool>();
  }

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) {
    final pending = _nextHealth;
    if (pending == null) return Future<bool>.value(false);
    _nextHealth = null;
    return pending.future;
  }
}

Future<void> _expandHomeConnectionDetails(WidgetTester tester) async {
  if (find.text('Control server').evaluate().isNotEmpty) return;
  final heading = find.text('Connection details');
  await tester.ensureVisible(heading);
  await tester.pumpAndSettle();
  await tester.tap(heading);
  await tester.pumpAndSettle();
}

class _ManualLaunchDaemon extends _FakeDaemonController {
  _ManualLaunchDaemon(super.api);
  static const command = 'sudo p2pnet-daemon --config ./demo.json';

  @override
  Future<DaemonCommandResult> start(AppSettings settings) async =>
      const DaemonCommandResult(
        ok: false,
        message: 'Use the manual launch command.',
        manualCommand: command,
      );
}
