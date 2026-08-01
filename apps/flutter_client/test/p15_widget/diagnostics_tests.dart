part of '../p15_widget_test.dart';

void _registerDiagnosticsTests() {
  testWidgets('Diagnostics renders summary, raw JSON, and copy action', (
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
      _TestApp(child: DiagnosticsPage(statusStore: stores.statusStore)),
    );

    expect(find.text('Summary'), findsOneWidget);
    expect(find.text('Raw /status JSON'), findsOneWidget);
    expect(find.text('Healthy'), findsWidgets);
    expect(find.text('Show JSON'), findsOneWidget);
    expect(
      find.textContaining('Full JSON is not rendered by default'),
      findsOneWidget,
    );

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

    expect(find.text('Copy'), findsWidgets);
    tester
        .widget<OutlinedButton>(
          find.widgetWithText(OutlinedButton, 'Copy').first,
        )
        .onPressed!();
    await tester.pump();

    expect(tester.takeException(), isNull);
  });
}
