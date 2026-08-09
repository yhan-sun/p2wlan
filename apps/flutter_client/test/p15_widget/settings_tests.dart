part of '../p15_widget_test.dart';

void _registerSettingsTests() {
  testWidgets('Settings validates diagnostics URL before saving', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
    ))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      _TestApp(
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    final diagnosticsField = find.byWidgetPredicate(
      (widget) =>
          widget is TextField &&
          widget.decoration?.labelText == 'Diagnostics URL',
    );
    await tester.enterText(diagnosticsField, 'ftp://127.0.0.1:39277');
    final saveButton = find.byKey(const Key('settings-save-button'));
    await tester.tap(saveButton);
    await tester.pump();

    expect(find.text('Diagnostics URL must use http or https'), findsOneWidget);
    expect(find.text('Diagnostics URL was not saved'), findsOneWidget);
  });

  testWidgets('Settings keeps network fields usable on narrow screens', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
    ))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      _TestApp(
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Network and Tunnel'), findsOneWidget);
    expect(find.text('Interface name'), findsOneWidget);
    expect(find.text('UDP advertise'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'Settings marks daemon configuration changes as pending restart',
    (tester) async {
      tester.view.physicalSize = const Size(800, 2400);
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
      expect(stores.statusStore.daemonReachable, isTrue);

      await tester.pumpWidget(
        _TestApp(
          child: SettingsPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );

      final mtuField = find.byWidgetPredicate(
        (widget) =>
            widget is TextField && widget.decoration?.labelText == 'MTU',
      );
      await tester.enterText(mtuField, '1280');
      await tester.tap(find.byKey(const Key('settings-save-button')));
      await tester.pump();
      for (
        var attempt = 0;
        attempt < 30 && stores.settingsStore.settings.mtu != 1280;
        attempt += 1
      ) {
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 100)),
        );
        await tester.pump();
      }
      for (
        var attempt = 0;
        attempt < 30 && find.text('P2WLAN restart required').evaluate().isEmpty;
        attempt += 1
      ) {
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 100)),
        );
        await tester.pump();
      }

      expect(stores.settingsStore.settings.mtu, 1280);
      expect(find.text('P2WLAN restart required'), findsOneWidget);
      expect(find.text('Restart and apply'), findsOneWidget);
    },
  );
}
