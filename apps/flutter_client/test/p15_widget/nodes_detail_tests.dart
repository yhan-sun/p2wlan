part of '../p15_widget_test.dart';

void _registerNodesDetailTests() {
  testWidgets('Nodes detail copies connection values and full node identity', (
    tester,
  ) async {
    final copied = <String>[];
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          copied.add((call.arguments as Map)['text'] as String);
        }
        return null;
      },
    );
    addTearDown(
      () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        null,
      ),
    );
    await _pumpPeerDetail(tester);
    for (final field in ['ip', 'endpoint']) {
      final action = find.byKey(Key('node-detail-copy-$field-peer-direct-001'));
      await tester.ensureVisible(action);
      await tester.pumpAndSettle();
      await tester.tap(action);
      await tester.pumpAndSettle();
      expect(find.text('Copied'), findsOneWidget);
    }
    final advanced = find.byKey(const Key('nodes-advanced-toggle'));
    await tester.ensureVisible(advanced);
    await tester.pumpAndSettle();
    await tester.tap(advanced);
    await tester.pumpAndSettle();
    final copyId = find.byKey(const Key('node-detail-copy-id-peer-direct-001'));
    await tester.ensureVisible(copyId);
    await tester.pumpAndSettle();
    await tester.tap(copyId);
    await tester.pumpAndSettle();
    expect(copied, ['10.20.0.11', '198.51.100.21:61111', 'peer-direct-001']);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump();
  });

  testWidgets(
    'Nodes detail keeps missing connection facts unknown and has no empty copy actions',
    (tester) async {
      await _pumpPeerDetail(
        tester,
        editPeer: (peer) {
          peer['virtual_ip'] = '';
          peer['endpoint'] = null;
          peer['relay_server'] = null;
          peer['nat_type'] = 'unknown';
          peer.remove('connected_for_ms');
        },
      );
      expect(find.text('Connected for'), findsOneWidget);
      expect(find.text('NAT type'), findsOneWidget);
      expect(find.text('0 s'), findsNothing);
      for (final field in ['ip', 'endpoint', 'relay']) {
        expect(
          find.byKey(Key('node-detail-copy-$field-peer-direct-001')),
          findsNothing,
        );
      }
      expect(find.text('Copy virtual IP'), findsNothing);
      final advanced = find.byKey(const Key('nodes-advanced-toggle'));
      await tester.ensureVisible(advanced);
      await tester.pumpAndSettle();
      await tester.tap(advanced);
      await tester.pumpAndSettle();
      expect(find.text('Copy ping command'), findsNothing);
      expect(
        find.byKey(const Key('node-detail-copy-id-peer-direct-001')),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Nodes detail clears current connection duration when its snapshot becomes stale',
    (tester) async {
      final stores = await _pumpPeerDetail(tester);
      expect(find.text('34s'), findsOneWidget);
      final api = stores.statusStore.diagnosticsApi as _FakeDiagnosticsApi;
      api.health = false;
      await stores.statusStore.refresh();
      await tester.pumpAndSettle();
      expect(find.text('34s'), findsNothing);
      expect(find.text('Stale'), findsWidgets);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Nodes detail uses reported traffic and the snapshot network for history',
    (tester) async {
      await _pumpPeerDetail(tester);
      expect(
        tester.widget<Text>(find.byKey(const Key('peer-traffic-upload'))).data,
        '11.8 KB',
      );
      expect(
        tester
            .widget<Text>(find.byKey(const Key('peer-traffic-download')))
            .data,
        '21.6 KB',
      );
      expect(
        tester.widget<Text>(find.byKey(const Key('peer-traffic-total'))).data,
        '33.4 KB',
      );
      final history = tester.widget<TrafficHistorySection>(
        find.byType(TrafficHistorySection),
      );
      expect(history.networkId, 'default');
      expect(history.peerId, 'peer-direct-001');
      expect(find.text('Current recorded traffic'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Nodes detail distinguishes a reported zero from missing traffic',
    (tester) async {
      await _pumpPeerDetail(
        tester,
        editPeer: (peer) {
          peer['bytes_sent'] = 0;
          peer.remove('bytes_received');
        },
      );
      expect(
        tester.widget<Text>(find.byKey(const Key('peer-traffic-upload'))).data,
        '0 B',
      );
      expect(
        tester
            .widget<Text>(find.byKey(const Key('peer-traffic-download')))
            .data,
        '—',
      );
      expect(
        tester.widget<Text>(find.byKey(const Key('peer-traffic-total'))).data,
        '—',
      );
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Nodes detail keeps explicit local scope traffic separate from peer counters',
    (tester) async {
      tester.view.physicalSize = const Size(800, 1000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.lightTheme,
          home: Scaffold(
            body: DeviceDetailsDialog(
              strings: AppStrings.fromCode('en'),
              content: const Text('Local device in this room'),
              networkId: 'room-a',
              current: true,
              trafficCounters: const TrafficCounters(
                uploadBytes: 1024,
                downloadBytes: 2048,
              ),
              serviceUptimeMs: 90000,
              transferBytesPerSecond: 4096,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(
        tester.widget<Text>(find.byKey(const Key('peer-traffic-total'))).data,
        '3.0 KB',
      );
      expect(find.text('4 KB/s'), findsOneWidget);
      expect(find.text(formatElapsedTime(90000)), findsOneWidget);
      final history = tester.widget<TrafficHistorySection>(
        find.byType(TrafficHistorySection),
      );
      expect(history.networkId, 'room-a');
      expect(history.peerId, isNull);
      expect(tester.takeException(), isNull);
    },
  );

  for (final variant in [
    (const Size(320, 740), 2.0, 'en'),
    (const Size(390, 844), 1.5, 'zh-Hans'),
  ]) {
    testWidgets(
      'Nodes detail retains connection facts with large text ${variant.$3}',
      (tester) async {
        await _pumpPeerDetail(
          tester,
          size: variant.$1,
          textScale: variant.$2,
          language: variant.$3,
          mobile: true,
        );
        final strings = AppStrings.fromCode(variant.$3);
        expect(find.byKey(const Key('nodes-mobile-detail')), findsOneWidget);
        final ip = find.byKey(const Key('node-detail-copy-ip-peer-direct-001'));
        await tester.ensureVisible(ip);
        await tester.pumpAndSettle();
        expect(ip.hitTestable(), findsOneWidget);
        final advanced = find.byKey(const Key('nodes-advanced-toggle'));
        await tester.ensureVisible(advanced);
        await tester.pumpAndSettle();
        await tester.tap(advanced);
        await tester.pumpAndSettle();
        final identity = find.byKey(
          const Key('node-detail-copy-id-peer-direct-001'),
        );
        await tester.ensureVisible(identity);
        await tester.pumpAndSettle();
        expect(identity.hitTestable(), findsOneWidget);
        expect(find.text(strings.nodeId), findsOneWidget);
        expect(tester.takeException(), isNull);
      },
    );
  }
}

Future<_Stores> _pumpPeerDetail(
  WidgetTester tester, {
  void Function(Map<String, dynamic> peer)? editPeer,
  Size size = const Size(800, 1200),
  double textScale = 1,
  String language = 'en',
  bool mobile = false,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final snapshot = (await tester.runAsync(() async {
    final original = await _loadFixtureSnapshot();
    final raw = jsonDecode(jsonEncode(original.raw)) as Map<String, dynamic>;
    editPeer?.call((raw['peers'] as List).first as Map<String, dynamic>);
    return DiagnosticsSnapshot.fromJson(raw);
  }))!;
  final stores = (await tester.runAsync(
    () => _makeStores(
      api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      deviceName: 'Demo workstation',
    ),
  ))!;
  addTearDown(stores.dispose);
  await stores.statusStore.refresh();
  await tester.pumpWidget(
    MaterialApp(
      theme: AppTheme.lightTheme,
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context)
            .copyWith(textScaler: TextScaler.linear(textScale)),
        child: child!,
      ),
      home: AppStringsScope(
        strings: AppStrings.fromCode(language),
        child: Scaffold(
          body: NodesPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
            capabilities: mobile
                ? PlatformCapabilities.fromPlatform('android')
                : null,
          ),
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
  final row = find.byKey(const Key('node-row-peer-direct-001'));
  await tester.ensureVisible(row);
  await tester.pumpAndSettle();
  await tester.tap(row);
  await tester.pumpAndSettle();
  return stores;
}
