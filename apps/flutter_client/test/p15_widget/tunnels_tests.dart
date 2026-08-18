part of '../p15_widget_test.dart';

void _registerTunnelsTests() {
  testWidgets(
    'Tunnels shows authoritative route Check/Repair, not a daemon restart',
    (tester) async {
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
          child: TunnelsPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );

      // The route panel exposes distinct check (read-only) and repair
      // (in-place, no restart) actions...
      expect(find.text('Check routes'), findsOneWidget);
      expect(find.text('Repair routes'), findsOneWidget);
      // ...and the misleading "restart daemon to rebuild routes" primary
      // action is gone (the heavier restart is a clearly-labelled secondary).
      expect(find.text('Restart daemon to rebuild routes'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('Tunnels keeps detail rows readable on narrow screens', (
    tester,
  ) async {
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
        child: TunnelsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Tunnel summary'), findsOneWidget);
    expect(find.text('Virtual Adapter'), findsOneWidget);
    expect(find.text('192.0.2.10:60207'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
