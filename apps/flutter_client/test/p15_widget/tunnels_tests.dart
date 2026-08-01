part of '../p15_widget_test.dart';

void _registerTunnelsTests() {
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
