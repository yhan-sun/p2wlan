part of '../p15_widget_test.dart';

String _trafficToken(String user) =>
    'a.${base64Url.encode(utf8.encode(jsonEncode({'user_id': user})))}.b';

DiagnosticsSnapshot _trafficSnapshot({
  int? sent = 1024,
  int? received = 2048,
  bool stale = false,
}) => DiagnosticsSnapshot.fromJson({
  'node_id': 'traffic-local',
  'network_id': 'default',
  'virtual_ip': '10.20.0.2',
  'process_id': 42,
  'uptime_ms': 120000,
  'revision': 1,
  'captured_revision': 1,
  'peer_snapshot_stale': stale,
  'health': {'status': 'healthy', 'control_connected': true},
  'stats': {
    'total_peers': 1,
    'total_bytes_sent': sent,
    'total_bytes_received': received,
  },
  'peers': [
    {
      'node_id': 'traffic-peer',
      'virtual_ip': '10.20.0.3',
      'device_name': 'Fixture laptop',
      'online': true,
      'state': 'relay',
      'active_path': 'relay',
      'relay': {'last_success_age_ms': 0},
      'bytes_sent': sent,
      'bytes_received': received,
    },
  ],
});

String? _trafficText(WidgetTester tester, String key) =>
    tester.widget<Text>(find.byKey(ValueKey(key))).data;

void _registerTrafficTests() {
  testWidgets(
    'Traffic history app owner records refreshes and exposes history to dialogs',
    (tester) async {
      final directory = (await tester.runAsync(
        () => Directory.systemTemp.createTemp('traffic-app-test-'),
      ))!;
      addTearDown(() => directory.deleteSync(recursive: true));
      final settings = SettingsStore(
        settingsFile: File('${directory.path}/settings.json'),
        tokenRepository: InMemorySecureTokenRepository(),
      );
      await tester.runAsync(() async {
        await settings.load();
        await settings.updateSettings(
          settings.settings.copyWith(
            deviceName: 'Traffic history test device',
            authToken: _trafficToken('traffic-member'),
            controlServer: 'https://control.example',
            languageCode: 'en',
            onboardingCompleted: true,
          ),
        );
      });
      final api = _FakeDiagnosticsApi(
        health: true,
        snapshot: _trafficSnapshot(),
      );
      final history = TrafficHistoryStore(persistent: false);
      await tester.pumpWidget(
        P2WlanApp(
          settingsStore: settings,
          diagnosticsApi: api,
          daemonController: _FakeDaemonController(api),
          trafficHistoryStore: history,
          autoCheckForUpdates: false,
          autoStartPolling: false,
          initialRefresh: false,
        ),
      );
      for (
        var i = 0;
        i < 10 && find.byType(DashboardPage).evaluate().isEmpty;
        i++
      ) {
        await tester.runAsync(
          () async => Future<void>.delayed(const Duration(milliseconds: 10)),
        );
        await tester.pump();
      }
      final page = tester.widget<DashboardPage>(find.byType(DashboardPage));
      await page.statusStore.refresh();
      expect(
        history.summary(settings: settings.settings)?.counters.totalBytes,
        0,
      );
      api.snapshot = _trafficSnapshot(sent: 2048, received: 4096);
      await page.statusStore.refresh();
      await tester.pump();
      expect(
        history.summary(settings: settings.settings)?.counters.totalBytes,
        3072,
      );
      expect(_trafficText(tester, 'home-traffic-current-total'), '6.0 KB');
      expect(
        _trafficText(tester, 'home-traffic-history-total'),
        'Saved total  3.0 KB',
      );
      final details = find.byKey(const Key('home-traffic-details'));
      await tester.ensureVisible(details);
      await tester.pumpAndSettle();
      await tester.tap(details);
      await tester.pumpAndSettle();
      expect(_trafficText(tester, 'traffic-history-total'), '3.0 KB');
      expect(find.text('Service uptime  2m 0s'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump();
    },
  );

  for (final sample in ['zero', 'missing', 'stale']) {
    testWidgets('Traffic overview preserves $sample semantics in details', (
      tester,
    ) async {
      final api = _FakeDiagnosticsApi(
        health: true,
        snapshot: _trafficSnapshot(
          sent: sample == 'missing'
              ? null
              : sample == 'zero'
              ? 0
              : 1024,
          received: sample == 'zero' ? 0 : 2048,
          stale: sample == 'stale',
        ),
      );
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
      expect(
        _trafficText(tester, 'home-traffic-current-total'),
        switch (sample) {
          'zero' => '0 B',
          'missing' => '—',
          _ => '3.0 KB',
        },
      );
      if (sample == 'stale') {
        expect(find.text('Last recorded values'), findsOneWidget);
      }
      await tester.ensureVisible(find.byKey(const Key('home-traffic-details')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('home-traffic-details')));
      await tester.pumpAndSettle();
      expect(find.text('Upload rate  —'), findsOneWidget);
      if (sample == 'stale') {
        expect(find.text('Service uptime  —'), findsOneWidget);
      }
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  for (final scenario in [(320.0, 2.0, 'en'), (390.0, 1.5, 'zh')]) {
    testWidgets(
      'Traffic details fit narrow large text ${scenario.$1} ${scenario.$3}',
      (tester) async {
        tester.view.physicalSize = Size(scenario.$1, 844);
        tester.view.devicePixelRatio = 1;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        final stores = (await tester.runAsync(
          () => _makeStores(
            api: _FakeDiagnosticsApi(
              health: true,
              snapshot: _trafficSnapshot(),
            ),
            authToken: _trafficToken('member'),
          ),
        ))!;
        addTearDown(stores.dispose);
        await stores.statusStore.refresh();
        final history = TrafficHistoryStore(persistent: false);
        addTearDown(history.dispose);
        await history.load();
        history.observe(
          settings: stores.settingsStore.settings,
          scopes: NetworkOverview.read(stores.statusStore).scopes,
        );
        await tester.pumpWidget(
          AppStringsScope(
            strings: AppStrings.fromCode(scenario.$3),
            child: MaterialApp(
              theme: AppTheme.lightTheme,
              builder: (context, child) => TrafficHistoryScope(
                store: history,
                settings: stores.settingsStore.settings,
                onRefresh: () {},
                child: MediaQuery(
                  data: MediaQuery.of(context)
                      .copyWith(textScaler: TextScaler.linear(scenario.$2)),
                  child: child!,
                ),
              ),
              home: Scaffold(
                body: DashboardPage(
                  settingsStore: stores.settingsStore,
                  statusStore: stores.statusStore,
                ),
              ),
            ),
          ),
        );
        await tester.ensureVisible(
          find.byKey(const Key('home-traffic-details')),
        );
        await tester.pumpAndSettle();
        expect(
          find.byKey(const Key('home-traffic-details')).hitTestable(),
          findsOneWidget,
        );
        await tester.tap(find.byKey(const Key('home-traffic-details')));
        await tester.pumpAndSettle();
        await tester.ensureVisible(
          find.byKey(const Key('traffic-history-total')),
        );
        await tester.pumpAndSettle();
        expect(_trafficText(tester, 'traffic-history-total'), '0 B');
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }
}
